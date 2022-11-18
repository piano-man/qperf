cmake_minimum_required(VERSION 3.6.0)
project(qperf VERSION 1.0.0 LANGUAGES C CXX)

add_subdirectory(extern)

add_executable(qperf main.c
    crypto_engine.h crypto_engine.c
    client.h client.c
    client_stream.h client_stream.c
    server.h server.c
    server_stream.h server_stream.c
    common.h common.c)

# target_include_directories(qperf INTERFACE "/proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/inc")
# target_include_directories(qperf INTERFACE "/proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/bindings/cc")

target_link_libraries(qperf PUBLIC quicly ev picotls)
# target_link_libraries(qperf INTERFACE /proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/bindings/cc/librt++.a)
# target_link_libraries(qperf INTERFACE /proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/libruntime.a)
# target_link_libraries(qperf INTERFACE /proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/libnet.a)
# target_link_libraries(qperf INTERFACE /proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/libbase.a)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(qperf INTERFACE Threads::Threads)


set (CMAKE_EXE_LINKER_FLAGS "-T /proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/base/base.ld") 
set (CMAKE_CXX_FLAGS "-fpermissive -std=c++0x")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#SET(SHENANGO_LIBRARIES "")
#SET(SHENANGO_INCLUDE_DIRECTORIES "")

# add shenango headers
list(APPEND SHENANGO_INCLUDE_DIRECTORIES "/proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/inc")
list(APPEND SHENANGO_INCLUDE_DIRECTORIES "/proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/bindings/cc")

# link shenango libraries
list(APPEND SHENANGO_LIBRARIES /proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/bindings/cc/librt++.a)
list(APPEND SHENANGO_LIBRARIES /proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/libruntime.a)
list(APPEND SHENANGO_LIBRARIES /proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/libnet.a)
list(APPEND SHENANGO_LIBRARIES /proj/quic-server-PG0/users/gagan/custom/decryption/caladan_quic/libbase.a)
list(APPEND SHENANGO_LIBRARIES -lpthread)

target_include_directories(qperf PUBLIC ${SHENANGO_INCLUDE_DIRECTORIES})
target_link_libraries(qperf PUBLIC ${SHENANGO_LIBRARIES})

target_compile_definitions(qperf PRIVATE QPERF_VERSION="${PROJECT_VERSION}")
target_compile_options(qperf PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
)

