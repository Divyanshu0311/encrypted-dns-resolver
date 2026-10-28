cmake_minimum_required(VERSION 3.20)
project(dns_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTING "Build the unit tests" ON)

find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)

# Everything except main.cpp, so the tests can reuse it without a second main()
set(DNS_LIB_SOURCES
    src/admission.cpp
    src/backend/Cache.cpp
    src/backend/ForwardingResolver.cpp
    src/backend/HostsFileResolver.cpp
    src/backend/RecursiveResolver.cpp
    src/backend/ZoneFile.cpp
    src/backend/ZoneFilesResolver.cpp
    src/block_list.cpp
    src/config.cpp
    src/deadline_timer.cpp
    src/dns_message.cpp
    src/DomainName.cpp
    src/dot_framer.cpp
    src/inflight_table.cpp
    src/IP.cpp
    src/load_balancer.cpp
    src/logger.cpp
    src/metrics.cpp
    src/middleware.cpp
    src/rate_limiter.cpp
    src/Records.cpp
    src/resolver_factory.cpp
    src/responder.cpp
    src/tls_context.cpp
    src/worker.cpp
)

# The DNS-over-TLS server loop uses epoll and eventfd, which only Linux has
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND DNS_LIB_SOURCES src/dot_server.cpp)
endif()

# Compiled once, linked into both the server and the tests (no archive/library produced)
add_library(dns_objs OBJECT ${DNS_LIB_SOURCES})
target_include_directories(dns_objs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(dns_objs PUBLIC cxx_std_23)
target_link_libraries(dns_objs PUBLIC Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

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

add_executable(load_gen tools/load_gen.cpp)
target_link_libraries(load_gen PRIVATE dns_objs)

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

    add_executable(dns_tests
        tests/main.cpp
        tests/test_admission.cpp
        tests/test_block_list.cpp
        tests/test_bounded_queue.cpp
        tests/test_config.cpp
        tests/test_deadline_timer.cpp
        tests/test_dns_message.cpp
        tests/test_domainname.cpp
        tests/test_dot_framer.cpp
        tests/test_hostsfileresolver.cpp
        tests/test_inflight_table.cpp
        tests/test_IP.cpp
        tests/test_load_balancer.cpp
        tests/test_metrics.cpp
        tests/test_middleware.cpp
        tests/test_rate_limiter.cpp
        tests/test_records.cpp
        tests/test_resolver_factory.cpp
        tests/test_responder.cpp
        tests/test_tls_context.cpp
        tests/test_types.cpp
        tests/test_worker.cpp
        tests/test_zonefile.cpp
        tests/test_zonefilesresolver.cpp
    )
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_sources(dns_tests PRIVATE tests/test_dot_server.cpp)
    endif()
    # tests/ on the include path so "support/*.hpp" resolve
    target_include_directories(dns_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    # Plain gtest, not gtest_main: tests/main.cpp provides main()
    target_link_libraries(dns_tests PRIVATE dns_objs GTest::gtest)

    include(GoogleTest)
    gtest_discover_tests(dns_tests)
endif()
