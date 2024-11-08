#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <pqxx/pqxx>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <iostream>
#include <string>
#include <fstream>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <algorithm>
#include <chrono>
#include <thread>

namespace beast = boost::beast;     
namespace http = beast::http;       
namespace net = boost::asio;        
using tcp = boost::asio::ip::tcp;
namespace json = boost::json;

// Пул соединений с базой данных
class ConnectionPool {
public:
    ConnectionPool(const std::string& conn_string, std::size_t pool_size) 
        : conn_string_(conn_string), pool_size_(pool_size) {
        for (std::size_t i = 0; i < pool_size_; ++i) {
            auto conn = std::make_shared<pqxx::connection>(conn_string_);
            if (conn->is_open()) {
                std::lock_guard<std::mutex> lock(mutex_);
                pool_.push(conn);
            } else {
                throw std::runtime_error("Unable to open database connection");
            }
        }
    }

    std::shared_ptr<pqxx::connection> getConnection() {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_.wait(lock, [this]() { return !pool_.empty(); });
        auto conn = pool_.front();
        pool_.pop();
        return conn;
    }

    void releaseConnection(std::shared_ptr<pqxx::connection> conn) {
        std::lock_guard<std::mutex> lock(mutex_);
        pool_.push(conn);
        cond_.notify_one();
    }

private:
    std::string conn_string_;
    std::size_t pool_size_;
    std::queue<std::shared_ptr<pqxx::connection>> pool_;
    std::mutex mutex_;
    std::condition_variable cond_;
};

// Чтение конфиденциальных данных из файла
json::object readSecrets(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        throw std::runtime_error("Unable to open secrets file");
    }
    std::string content((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
    json::value jv = json::parse(content);
    return jv.as_object();
}

// Генерация токена
std::string generateToken() {
    boost::uuids::random_generator generator;
    boost::uuids::uuid uuid = generator();
    return to_string(uuid);
}

// Аутентификация клиента
bool authenticateClient(ConnectionPool& db_pool, const std::string& client_id, const std::string& client_secret) {
    try {
        auto conn = db_pool.getConnection();
        pqxx::work txn(*conn);
        pqxx::result res = txn.exec_prepared("authenticate_client", client_id);
        if (!res.empty() && res[0]["client_secret"].as<std::string>() == client_secret) {
            db_pool.releaseConnection(conn);
            return true;
        }
        db_pool.releaseConnection(conn);
    } catch (const std::exception &e) {
        std::cerr << "DB connection error: " << e.what() << std::endl;
    }
    return false;
}

// Проверка валидности токена
bool isTokenValid(ConnectionPool& db_pool, const std::string& token) {
    try {
        auto conn = db_pool.getConnection();
        pqxx::work txn(*conn);
        pqxx::result res = txn.exec_prepared("get_token", token);
        if (!res.empty()) {
            std::string dateTimeStr = res[0]["expiration_time"].as<std::string>();
            std::tm exp_tm = {};
            std::istringstream ss(dateTimeStr);
            ss >> std::get_time(&exp_tm, "%Y-%m-%d %H:%M:%S");
            if (ss.fail()) {
                std::cerr << "Error parsing expiration time format: " << dateTimeStr << std::endl;
                db_pool.releaseConnection(conn);
                return false;
            }
            std::time_t exp_time_t = timegm(&exp_tm);
            if (exp_time_t == -1) {
                std::cerr << "Error converting expiration time with timegm" << std::endl;
                db_pool.releaseConnection(conn);
                return false;
            }
            auto exp_time = std::chrono::system_clock::from_time_t(exp_time_t);
            auto now = std::chrono::system_clock::now();
            db_pool.releaseConnection(conn);
            return now < exp_time;
        }
        db_pool.releaseConnection(conn);
    } catch (const std::exception &e) {
        std::cerr << "Token verification error: " << e.what() << std::endl;
    }
    return false;
}

// Обработка запроса на создание токена
void handleToken(ConnectionPool& db_pool, const http::request<http::string_body>& req, http::response<http::string_body>& res) {
    try {
        auto params = json::parse(req.body()).as_object();

        // Проверка наличия необходимых параметров
        if (!params.contains("client_id") || !params["client_id"].is_string() ||
            !params.contains("client_secret") || !params["client_secret"].is_string() ||
            !params.contains("scope") || !params["scope"].is_string() ||
            !params.contains("grant_type") || !params["grant_type"].is_string()) {
            
            json::object errorResponse;
            errorResponse["error"] = "invalid_request";
            errorResponse["error_description"] = "Missing or invalid parameter types.";

            res.result(http::status::bad_request);
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(errorResponse);
            res.prepare_payload();
            return;
        }

        std::string client_id = params["client_id"].as_string().c_str();
        std::string client_secret = params["client_secret"].as_string().c_str();
        std::string requested_scope = params["scope"].as_string().c_str();
        std::string grant_type = params["grant_type"].as_string().c_str();

        if (grant_type != "client_credentials") {
            json::object errorResponse;
            errorResponse["error"] = "unsupported_grant_type";
            errorResponse["error_description"] = "grant_type must be 'client_credentials'";

            res.result(http::status::bad_request);
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(errorResponse);
            res.prepare_payload();
            return;
        }

        if (authenticateClient(db_pool, client_id, client_secret)) {
            auto conn = db_pool.getConnection();
            pqxx::work txn(*conn);

            // Получение scope клиента
            pqxx::result res_db = txn.exec_prepared("get_scope", client_id);

            if (res_db.empty()) {
                json::object errorResponse;
                errorResponse["error"] = "invalid_client";
                errorResponse["error_description"] = "Client not found";
                res.result(http::status::unauthorized);
                res.set(http::field::content_type, "application/json");
                res.body() = json::serialize(errorResponse);
                res.prepare_payload();
                db_pool.releaseConnection(conn);
                return;
            }
            
            json::array allowed_scopes_json = json::parse(res_db[0]["scope"].c_str()).as_array();
            std::vector<std::string> allowed_scopes;
            for (const auto& scope_item : allowed_scopes_json) {
                allowed_scopes.emplace_back(scope_item.as_string().c_str());
            }

            // Фильтруем requested_scope, чтобы оставить только разрешенные области доступа
            std::vector<std::string> final_scopes;
            std::istringstream req_stream(requested_scope);
            std::string scope;
            while (req_stream >> scope) {
                if (std::find(allowed_scopes.begin(), allowed_scopes.end(), scope) != allowed_scopes.end()) {
                    final_scopes.emplace_back(scope);
                }
            }

            // Если ни один scope не совпал, возвращаем ошибку
            if (final_scopes.empty()) {
                json::object errorResponse;
                errorResponse["error"] = "invalid_scope";
                errorResponse["error_description"] = "None of the requested scopes are permitted for this client.";
                res.result(http::status::bad_request);
                res.set(http::field::content_type, "application/json");
                res.body() = json::serialize(errorResponse);
                res.prepare_payload();
                db_pool.releaseConnection(conn);
                return;
            }

            // Формируем строку scopes для SQL-запроса
            std::string scopes_sql;
            for (size_t i = 0; i < final_scopes.size(); ++i) {
                scopes_sql += txn.quote(final_scopes[i]);
                if (i != final_scopes.size() - 1) {
                    scopes_sql += ", ";
                }
            }

            // Удаляем существующие токены для клиента
            txn.exec0("DELETE FROM public.token WHERE client_id = " + txn.quote(client_id));
            std::string access_token = generateToken();

            // Вставляем новый токен
            txn.exec0("INSERT INTO public.token (client_id, access_scope, access_token, expiration_time) VALUES (" +
                      txn.quote(client_id) + ", ARRAY[" + scopes_sql + "], " + txn.quote(access_token) + 
                      ", CURRENT_TIMESTAMP + INTERVAL '2 hours')");
            txn.commit();
            db_pool.releaseConnection(conn);

            // Формируем JSON-ответ
            json::object jsonResponse;
            jsonResponse["access_token"] = access_token;
            jsonResponse["expires_in"] = 7200;
            jsonResponse["refresh_token"] = "";
            jsonResponse["scope"] = final_scopes;
            jsonResponse["security_level"] = "normal";
            jsonResponse["token_type"] = "Bearer";

            res.result(http::status::ok);
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(jsonResponse);
            res.prepare_payload();
        } else {
            json::object errorResponse;
            errorResponse["error"] = "invalid_client";
            errorResponse["error_description"] = "Authentication Error";
            res.result(http::status::unauthorized);
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(errorResponse);
            res.prepare_payload();
        }
    }

// Обработка запроса на проверку токена
void handleCheck(ConnectionPool& db_pool, const http::request<http::string_body>& req, http::response<http::string_body>& res) {
    std::string authHeader = std::string(req[http::field::authorization]);
    if (authHeader.find("Bearer ") != 0) {
        json::object jsonResponse;
        jsonResponse["error"] = "invalid_request";
        jsonResponse["error_description"] = "Authorization header must start with Bearer";
        res.result(http::status::bad_request);
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(jsonResponse);
        res.prepare_payload();
        return;
    }

    std::string token = authHeader.substr(7); // Убираем "Bearer "

    if (isTokenValid(db_pool, token)) {
        try {
            auto conn = db_pool.getConnection();
            pqxx::work txn(*conn);

            pqxx::result res_db = txn.exec_prepared("get_token_details", token);

            if (!res_db.empty()) {
                std::string client_id = res_db[0]["client_id"].c_str();
                json::array scope_array = json::parse(res_db[0]["access_scope"].c_str()).as_array();

                json::object jsonResponse;
                jsonResponse["client_id"] = client_id;
                jsonResponse["scope"] = scope_array;

                res.result(http::status::ok);
                res.set(http::field::content_type, "application/json");
                res.body() = json::serialize(jsonResponse);
            } else {
                json::object jsonResponse;
                jsonResponse["error"] = "Token not found";
                res.result(http::status::unauthorized);
                res.set(http::field::content_type, "application/json");
                res.body() = json::serialize(jsonResponse);
            }
            res.prepare_payload();
            db_pool.releaseConnection(conn);
        } catch (const std::exception &e) {
            std::cerr << "Error in handleCheck: " << e.what() << std::endl;
            json::object jsonResponse;
            jsonResponse["error"] = "server_error";
            res.result(http::status::internal_server_error);
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(jsonResponse);
            res.prepare_payload();
        } 
    } else {
        json::object jsonResponse;
        jsonResponse["error"] = "Invalid or expired token";
        res.result(http::status::unauthorized);
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(jsonResponse);
        res.prepare_payload();
    }
}

// Класс для управления сессией
class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, ConnectionPool& db_pool)
        : socket_(std::move(socket)), db_pool_(db_pool), buffer_(), res_() {}

    void start() {
        readRequest();
    }

private:
    tcp::socket socket_;
    ConnectionPool& db_pool_;
    beast::flat_buffer buffer_;
    http::response<http::string_body> res_;

    void readRequest() {
        auto self = shared_from_this();
        http::async_read(socket_, buffer_, req_,
            [self](beast::error_code ec, std::size_t bytes_transferred) {
                boost::ignore_unused(bytes_transferred);
                if (!ec) {
                    self->processRequest();
                }
            });
    }

    void processRequest() {
        if (req_.method() == http::verb::post && req_.target() == "/token") {
            handleToken(db_pool_, req_, res_);
        } else if (req_.method() == http::verb::get && req_.target() == "/check") {
            handleCheck(db_pool_, req_, res_);
        } else {
            res_.result(http::status::not_found);
            res_.set(http::field::content_type, "text/plain");
            res_.body() = "Not Found";
            res_.prepare_payload();
        }

        writeResponse();
    }

    void writeResponse() {
        auto self = shared_from_this();
        http::async_write(socket_, res_,
            [self](beast::error_code ec, std::size_t bytes_transferred) {
                boost::ignore_unused(bytes_transferred);
                if (!ec) {
                    if (self->req_[http::field::connection] != "close") {
                        self->readRequest();
                    } else {
                        self->socket_.shutdown(tcp::socket::shutdown_send, ec);
                    }
                }
            });
    }

    http::request<http::string_body> req_;
};

// Обработка запросов
class Server {
public:
    Server(net::io_context& ioc, tcp::endpoint endpoint, ConnectionPool& db_pool)
        : acceptor_(ioc), db_pool_(db_pool) {
        beast::error_code ec;

        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            throw beast::system_error(ec);
        }

        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            throw beast::system_error(ec);
        }

        acceptor_.bind(endpoint, ec);
        if (ec) {
            throw beast::system_error(ec);
        }

        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            throw beast::system_error(ec);
        }
    }

    void run() {
        doAccept();
    }

private:
    tcp::acceptor acceptor_;
    ConnectionPool& db_pool_;

    void doAccept() {
        acceptor_.async_accept(
            net::make_strand(acceptor_.get_executor()),
            [this](beast::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<Session>(std::move(socket), db_pool_)->start();
                }
                doAccept();
            });
    }
};

int main() {
    try {
        // Чтение секретов
        json::object secrets = readSecrets("/etc/vault/secrets/config.json");
        const std::string DB_CONNECTION = secrets["DB_CONNECTION"].as_string().c_str();

        // Инициализация пула соединений
        ConnectionPool db_pool(DB_CONNECTION, 100); // Оптимальный размер пула

        // Подготовка подготовленных запросов
        {
            auto conn = db_pool.getConnection();
            pqxx::work txn(*conn);
            txn.conn().prepare("authenticate_client", "SELECT client_secret FROM public.user WHERE client_id = $1");
            txn.conn().prepare("get_scope", "SELECT scope FROM public.user WHERE client_id = $1");
            txn.conn().prepare("get_token", "SELECT expiration_time FROM public.token WHERE access_token = $1");
            txn.conn().prepare("get_token_details", "SELECT u.client_id, t.access_scope FROM public.token t JOIN public.user u ON t.client_id = u.client_id WHERE t.access_token = $1");
            txn.commit();
            db_pool.releaseConnection(conn);
        }

        // Инициализация Boost.Asio
        net::io_context ioc{1};

        // Создание сервера
        tcp::endpoint endpoint{tcp::v4(), 8080};
        Server server(ioc, endpoint, db_pool);
        server.run();

        // Запуск потоков
        std::vector<std::thread> threads;
        auto thread_count = std::thread::hardware_concurrency();
        threads.reserve(thread_count - 1);
        for (std::size_t i = 0; i < thread_count - 1; ++i) {
            threads.emplace_back([&ioc] { ioc.run(); });
        }
        ioc.run();

        // Присоединение потоков
        for (auto& t : threads) {
            t.join();
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
