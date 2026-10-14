cmake_minimum_required(VERSION 3.25)
project(SecYS LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)

add_executable(secys_cli client_cli/main.cpp)
target_include_directories(secys_cli PRIVATE common)
target_compile_options(secys_cli PRIVATE /W4 /utf-8)
target_compile_definitions(secys_cli PRIVATE _WIN32_WINNT=0x0A00)
target_link_libraries(secys_cli PRIVATE unofficial-sodium::sodium asio::asio)

add_executable(secys_server server/main.cpp)
target_include_directories(secys_server PRIVATE common)
target_compile_options(secys_server PRIVATE /W4 /utf-8)
target_compile_definitions(secys_server PRIVATE _WIN32_WINNT=0x0A00)
target_link_libraries(secys_server PRIVATE asio::asio)

