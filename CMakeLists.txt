cmake_minimum_required(VERSION 3.20)
project(dns_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTING "Build the unit tests" ON)

find_package(Threads REQUIRED)

# All sources under src/ (CONFIGURE_DEPENDS re-checks the glob on each build)
file(GLOB_RECURSE DNS_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

# Everything except main.cpp, so the tests can reuse it without a second main()
set(DNS_LIB_SOURCES ${DNS_SOURCES})
list(FILTER DNS_LIB_SOURCES EXCLUDE REGEX "/main\\.cpp$")

# Compiled once, linked into both the server and the tests (no archive/library produced)
add_library(dns_objs OBJECT ${DNS_LIB_SOURCES})
target_include_directories(dns_objs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(dns_objs PUBLIC cxx_std_23)
target_link_libraries(dns_objs PUBLIC Threads::Threads)

# inet_pton / inet_ntop come from Winsock on Windows
if(WIN32)
    target_link_libraries(dns_objs PUBLIC ws2_32)
endif()

if(MSVC)
    target_compile_options(dns_objs PRIVATE /W4)
else()
    target_compile_options(dns_objs PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# Server executable
# ---------------------------------------------------------------------------
add_executable(dns_server src/main.cpp)
target_link_libraries(dns_server PRIVATE dns_objs)

# ---------------------------------------------------------------------------
# Tests (GoogleTest)
# ---------------------------------------------------------------------------
if(BUILD_TESTING)
    include(CTest)
    include(FetchContent)

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.18.0
    )
    # Use the dynamic CRT on Windows, matching the main target
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    file(GLOB_RECURSE DNS_TEST_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp"
    )

    add_executable(dns_tests ${DNS_TEST_SOURCES})
    target_link_libraries(dns_tests PRIVATE dns_objs GTest::gtest_main)

    include(GoogleTest)
    gtest_discover_tests(dns_tests)
endif()
