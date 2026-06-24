cmake_minimum_required(VERSION 3.16)
project(DigitalSigner VERSION 2.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(Qt5 REQUIRED COMPONENTS Core Widgets)
find_package(OpenSSL REQUIRED)

# ====================== Main Application ======================
add_executable(DigitalSigner
    src/main.cpp

    src/MainWindow.cpp
    include/MainWindow.h

    src/KeyManager.cpp
    include/KeyManager.h

    src/Signer.cpp
    include/Signer.h

    src/Verifier.cpp
    include/Verifier.h

    src/HashUtils.cpp
    include/HashUtils.h
)

# Явно добавляем header с Q_OBJECT
set_target_properties(DigitalSigner PROPERTIES 
    AUTOMOC ON
)

target_include_directories(DigitalSigner PRIVATE include)
target_link_libraries(DigitalSigner PRIVATE 
    Qt5::Core 
    Qt5::Widgets 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# ====================== Tests ======================
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(DigitalSignerTests
    tests/test_HashUtils.cpp
    src/HashUtils.cpp
)

target_include_directories(DigitalSignerTests PRIVATE include)
target_link_libraries(DigitalSignerTests PRIVATE
    gtest_main
    Qt5::Core
    OpenSSL::SSL
    OpenSSL::Crypto
)

add_test(NAME DigitalSignerTests COMMAND DigitalSignerTests)
# ====================== Install (для Docker) ======================
install(TARGETS DigitalSigner
    RUNTIME DESTINATION bin
)

message(STATUS "✅ CMake configured successfully!")
message(STATUS "Run: mingw32-make -j2")