# Используем базовый образ с GCC
FROM gcc:latest

# Устанавливаем базовые зависимости
RUN apt-get clean && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libpqxx-dev \
    cmake \
    make \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*



# Устанавливаем Boost из исходников (с поддержкой Boost.JSON)
WORKDIR /boost
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.81.0/source/boost_1_81_0.zip && \
    unzip boost_1_81_0.zip && cd boost_1_81_0 && \
    ./bootstrap.sh --with-libraries=system,thread,json && \
    ./b2 install

# Указываем путь к библиотекам Boost
ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"
# Копируем исходный код в контейнер
WORKDIR /app
COPY . .

# Собираем приложение
RUN g++ -std=c++17 -o app main.cpp -lpqxx -lpq -lboost_system -lboost_thread -lboost_json -pthread

# Открываем порт приложения
EXPOSE 8080

# Запускаем приложение
CMD ["./app"]
