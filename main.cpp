#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <pqxx/pqxx>
#include <iostream>
#include <ctime>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <string>


#include <iomanip>
#include <sstream>
#include <stdexcept>

#include <boost/asio/steady_timer.hpp> // Подключаем steady_timer для тайм-аута
#include <chrono>

namespace beast = boost::beast;     
namespace http = beast::http;       
namespace net = boost::asio;        
using tcp = boost::asio::ip::tcp;
namespace json = boost::json;

// const std::string DB_CONNECTION = "dbname=tokens user=postgres password=pass123";
// const std::string DB_CONNECTION = "host=localhost port=5432 dbname=tokens user=postgres password=pass123";
const std::string DB_CONNECTION = "host=db port=5432 dbname=tokens user=postgres password=pass123";

// Генерация уникального токена
// std::string generateToken() {
//     return "e3b0c44298fc1c149afbf4c8...";  // Для простоты возвращаем статичный токен
// }

std::string generateToken() {
    boost::uuids::random_generator generator;
    boost::uuids::uuid uuid = generator();
    return to_string(uuid);
}

// Проверка client_id и client_secret в базе данных
bool authenticateClient(const std::string& client_id, const std::string& client_secret) {
    try {
        pqxx::connection conn(DB_CONNECTION);
        pqxx::work txn(conn);
        pqxx::result res = txn.exec("SELECT client_secret FROM public.user WHERE client_id = " + txn.quote(client_id));

        if (!res.empty() && res[0]["client_secret"].as<std::string>() == client_secret) {
            return true;
        }
    } catch (const std::exception &e) {
        std::cerr << "DB connection error: " << e.what() << std::endl;
    }
    return false;
}

// Проверка токена в базе данных
// bool isTokenValid(const std::string& token) {
//     try {
//         pqxx::connection conn(DB_CONNECTION);
//         pqxx::work txn(conn);

//         pqxx::result res = txn.exec("SELECT expiration_time FROM public.token WHERE access_token = " + txn.quote(token));
//         if (!res.empty()) {
//             std::time_t now = std::time(nullptr);
//             std::tm exp_tm = {};
//             // std::istringstream ss(res[0]["expiration_time"].as<std::string>());
//             // ss >> std::get_time(&exp_tm, "%Y-%m-%d %H:%M:%S");
//             std::string dateTimeStr = res[0]["expiration_time"].as<std::string>();
//             std::istringstream ss(dateTimeStr);

//             int year, month, day, hour, minute, second;
//             char dash1, dash2, space, colon1, colon2;

//             if (ss >> year >> dash1 >> month >> dash2 >> day >> space >> hour >> colon1 >> minute >> colon2 >> second) {
//                 exp_tm.tm_year = year - 1900;
//                 exp_tm.tm_mon = month - 1;
//                 exp_tm.tm_mday = day;
//                 exp_tm.tm_hour = hour;
//                 exp_tm.tm_min = minute;
//                 exp_tm.tm_sec = second;
//             } else {
//                 // Обработка ошибки, если строка времени не соответствует формату
//                 std::cerr << "Error parsing date and time" << std::endl;
//             }

//             std::time_t exp_time = std::mktime(&exp_tm);

//             return std::difftime(exp_time, now) > 0;
//         }
//     } catch (const std::exception &e) {
//         std::cerr << "Token verification error: " << e.what() << std::endl;
//     }
//     return false;
// }


bool isTokenValid(const std::string& token) {
    try {
        pqxx::connection conn(DB_CONNECTION);
        pqxx::work txn(conn);

        pqxx::result res = txn.exec("SELECT expiration_time AT TIME ZONE 'UTC' AS expiration_time FROM public.token WHERE access_token = " + txn.quote(token));
        if (!res.empty()) {
            std::string dateTimeStr = res[0]["expiration_time"].as<std::string>();
            std::cout << "expiration_time from DB (UTC): " << dateTimeStr << std::endl;
            std::istringstream ss(dateTimeStr);

            std::tm exp_tm = {};
            ss >> std::get_time(&exp_tm, "%Y-%m-%d %H:%M:%S");

            if (ss.fail()) {
                std::cerr << "Error parsing expiration time format: " << dateTimeStr << std::endl;
                return false;
            }

            // Используем timegm для преобразования времени в UTC
            std::time_t exp_time_t = timegm(&exp_tm);
            if (exp_time_t == -1) {
                std::cerr << "Error converting expiration time with timegm" << std::endl;
                return false;
            }
            auto exp_time = std::chrono::system_clock::from_time_t(exp_time_t);

            // Получаем текущее время в UTC
            auto now = std::chrono::system_clock::now();
            std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);

            std::cout << "Current time (UTC): " << std::ctime(&now_time_t)
                      << "Expiration time (UTC): " << std::ctime(&exp_time_t) << std::endl;

            // Сравниваем время
            return now < exp_time;
        } else {
            std::cerr << "Token not found in database: " << token << std::endl;
        }
    } catch (const std::exception &e) {
        std::cerr << "Token verification error: " << e.what() << std::endl;
    }
    return false;
}






// Эндпоинт для создания токена
void handleToken(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    auto params = json::parse(req.body()).as_object();

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
    // std::string scope = params["scope"].as_string().c_str();
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
        return; // Завершаем функцию, так как grant_type неверный
    }

    if (authenticateClient(client_id, client_secret)) {
        try {
            pqxx::connection conn(DB_CONNECTION);
            pqxx::work txn(conn);

//
            //pqxx::result res_db = txn.exec("SELECT scope FROM public.user WHERE client_id = " + txn.quote(client_id));
            pqxx::result res_db = txn.exec("SELECT array_to_json(scope) AS scope FROM public.user WHERE client_id = " + txn.quote(client_id));

            if (res_db.empty()) {
                json::object errorResponse;
                errorResponse["error"] = "invalid_client";
                errorResponse["error_description"] = "Client not found";
                res.result(http::status::unauthorized);
                res.set(http::field::content_type, "application/json");
                res.body() = json::serialize(errorResponse);
                res.prepare_payload();
                return;
            }
            
            // Преобразуем массив scope из базы данных в список строк
            // std::vector<std::string> allowed_scopes;
            // for (const auto& scope_item : res_db[0]["scope"].as_array()) {
            //     allowed_scopes.push_back(scope_item.as<std::string>());
            // }

            // json::array allowed_scopes_json = res_db[0]["scope"].as<json::array>();
            // std::vector<std::string> allowed_scopes;
            // for (auto& scope_item : allowed_scopes_json) {
            //     allowed_scopes.push_back(scope_item.as_string().c_str());
            // }
            json::array allowed_scopes_json = json::parse(res_db[0]["scope"].c_str()).as_array();
            std::vector<std::string> allowed_scopes;
            for (const auto& scope_item : allowed_scopes_json) {
                allowed_scopes.push_back(scope_item.as_string().c_str());
            }

            // Фильтруем `requested_scope`, чтобы оставить только разрешенные области доступа
            std::string final_scope;
            std::istringstream req_stream(requested_scope);
            std::string scope;
            while (req_stream >> scope) {
                if (std::find(allowed_scopes.begin(), allowed_scopes.end(), scope) != allowed_scopes.end()) {
                    if (!final_scope.empty()) {
                        final_scope += " ";
                    }
                    final_scope += scope;
                }
            }

            // Если ни один scope не совпал, возвращаем ошибку
            if (final_scope.empty()) {
                json::object errorResponse;
                errorResponse["error"] = "invalid_scope";
                errorResponse["error_description"] = "None of the requested scopes are permitted for this client.";
                res.result(http::status::bad_request);
                res.set(http::field::content_type, "application/json");
                res.body() = json::serialize(errorResponse);
                res.prepare_payload();
                return;
            }


//


            txn.exec0("DELETE FROM public.token WHERE client_id = " + txn.quote(client_id));
            std::string access_token = generateToken();
            txn.exec0("INSERT INTO public.token (client_id, access_scope, access_token, expiration_time) VALUES (" +
                      txn.quote(client_id) + ", ARRAY[" + txn.quote(scope) + "], " + txn.quote(access_token) + 
                      ", CURRENT_TIMESTAMP + INTERVAL '2 hours')");
            txn.commit();

            json::object jsonResponse;
            jsonResponse["access_token"] = access_token;
            jsonResponse["expires_in"] = 7200;
            jsonResponse["refresh_token"] = "";
            jsonResponse["scope"] = final_scope;
            jsonResponse["security_level"] = "normal";
            jsonResponse["token_type"] = "Bearer";

            res.result(http::status::ok);
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(jsonResponse);
        } catch (const std::exception &e) {
            res.result(http::status::internal_server_error);
            res.body() = "Server error";
        }
    } else {
        res.result(http::status::unauthorized);
        res.body() = "Authentication Error";
    }
    res.prepare_payload();
}

// Эндпоинт для проверки токена
void handleCheck(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    // std::string authHeader = req[http::field::authorization].to_string();
    std::string authHeader = std::string(req[http::field::authorization]);
    std::string token = authHeader.substr(authHeader.find(" ") + 1);

    if (isTokenValid(token)) {
        // json::object jsonResponse;
        // jsonResponse["scope"] = "push_send";

        // res.result(http::status::ok);
        // res.set(http::field::content_type, "application/json");
        // res.body() = json::serialize(jsonResponse);
        try {
            // Открываем соединение с базой данных
            pqxx::connection conn(DB_CONNECTION);
            pqxx::work txn(conn);

            // Запрашиваем access_scope, связанный с данным токеном
            //pqxx::result res_db = txn.exec("SELECT access_scope FROM public.token WHERE access_token = " + txn.quote(token));
            // pqxx::result res_db = txn.exec(
            //     "SELECT t.access_scope, u.client_id "
            //     "FROM public.token t "
            //     "JOIN public.user u ON t.client_id = u.client_id "
            //     "WHERE t.access_token = " + txn.quote(token));
            pqxx::result res_db = txn.exec(
                "SELECT array_to_json(t.access_scope) AS access_scope, u.client_id "
                "FROM public.token t "
                "JOIN public.user u ON t.client_id = u.client_id "
                "WHERE t.access_token = " + txn.quote(token));

            if (!res_db.empty()) {
                // Извлекаем client_id
                // std::string client_id = res_db[0]["client_id"].c_str();
                // // Извлекаем scope из результата запроса
                // std::vector<std::string> scopes;
                // for (const auto& scope_item : res_db[0]["access_scope"].as_array()) {
                //     scopes.push_back(scope_item.c_str());
                // }
                std::string client_id = res_db[0]["client_id"].c_str();
                // Извлекаем access_scope из результата запроса
                // std::string access_scope_str = res_db[0]["access_scope"].c_str();
                json::array scope_array = json::parse(res_db[0]["access_scope"].c_str()).as_array();
                // boost::json::array scope_array;
                // std::istringstream scope_stream(access_scope_str);
                // std::string scope;
                // while (std::getline(scope_stream, scope, ',')) {
                //     // scope_array.push_back(scope);
                //     scope_array.push_back(json::value(scope));
                // }

                // Формируем JSON-ответ с `scope`
                json::object jsonResponse;
                jsonResponse["client_id"] = client_id;
                // jsonResponse["scope"] = scopes;
                jsonResponse["scope"] = scope_array;

                res.result(http::status::ok);
                res.set(http::field::content_type, "application/json");
                res.body() = json::serialize(jsonResponse);
            } else {
                // Если токен не найден, возвращаем ошибку
                json::object jsonResponse;
                jsonResponse["error"] = "Token not found";
                res.result(http::status::unauthorized);
                res.body() = json::serialize(jsonResponse);
            }
        } catch (const std::exception &e) {
            // Обработка ошибки базы данных
            std::cerr << "Token verification error: " << e.what() << std::endl;
            res.result(http::status::internal_server_error);
            res.body() = "Server error";
        } 
    } else {
        json::object jsonResponse;
        jsonResponse["error"] = "Invalid or expired token";
        res.result(http::status::unauthorized);
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(jsonResponse);
    }
    res.prepare_payload();
}

// Основная функция для обработки запросов
// реализация без keep alive
// void do_session(tcp::socket& socket) {
//     try {
//         beast::flat_buffer buffer;
//         http::request<http::string_body> req;
//         http::response<http::string_body> res;

//         http::read(socket, buffer, req);

//         if (req.method() == http::verb::post && req.target() == "/token") {
//             handleToken(req, res);
//         } else if (req.method() == http::verb::get && req.target() == "/check") {
//             handleCheck(req, res);
//         } else {
//             res.result(http::status::not_found);
//             res.body() = "Not Found. url that you use is not correct. only /token and /check";
//             res.prepare_payload();
//         }

//         http::write(socket, res);
//     } catch (const beast::system_error& se) {
//         if (se.code() != http::error::end_of_stream)
//             std::cerr << "Error: " << se.code().message() << std::endl;
//     }
//     socket.shutdown(tcp::socket::shutdown_send);
// }
void do_session(tcp::socket socket) {
    try {
        beast::flat_buffer buffer;
        boost::asio::steady_timer timer(socket.get_executor());

        // Начало цикла для обработки нескольких запросов на одном соединении
        while (true) {
            http::request<http::string_body> req;
            http::response<http::string_body> res;

            timer.expires_after(std::chrono::seconds(20));

            // Ожидание выполнения операции или тайм-аута
            timer.async_wait([&socket](const boost::system::error_code& ec) {
                if (!ec) {
                    // Если таймер сработал без ошибок, закрываем сокет
                    socket.close();
                }
            });

            // Чтение запроса
            http::read(socket, buffer, req);

            timer.cancel();
            // Обработка запроса в зависимости от пути
            if (req.method() == http::verb::post && req.target() == "/token") {
                handleToken(req, res);
            } else if (req.method() == http::verb::get && req.target() == "/check") {
                handleCheck(req, res);
            } else {
                res.result(http::status::not_found);
                res.body() = "Not Found";
                res.prepare_payload();
            }

            // Если клиент указал `Connection: close`, закрываем соединение после ответа
            if (req[http::field::connection] == "close") {
                res.set(http::field::connection, "close");
                http::write(socket, res);
                break; // Выходим из цикла и закрываем сокет
            } else {
                res.set(http::field::connection, "keep-alive");
                http::write(socket, res);
            }

            // Очищаем буфер для следующего запроса
            buffer.consume(buffer.size());

            // Устанавливаем тайм-аут на 20 секунд
            // socket.expires_after(std::chrono::seconds(20));
        }
    } catch (const beast::system_error& se) {
        if (se.code() != http::error::end_of_stream)
            std::cerr << "Error: " << se.code().message() << std::endl;
    }

    // Закрываем соединение после завершения всех запросов
    socket.shutdown(tcp::socket::shutdown_send);
}

int main() {
    try {
        net::io_context ioc;
        tcp::acceptor acceptor(ioc, {tcp::v4(), 8080});

        while (true) {
            tcp::socket socket(ioc);
            acceptor.accept(socket);
            // std::thread{std::bind(&do_session, std::move(socket))}.detach();
            std::thread{&do_session, std::move(socket)}.detach();
        }
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}



