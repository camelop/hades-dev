cmake_minimum_required(VERSION 3.15)
project(privshare-agg)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fopenmp")

include_directories(src)
include_directories(lib/macaron_base64)
include_directories(lib/nlohmann_json)
include_directories(lib/picosha2)

# executables
add_executable(keygen
        src/keygen.cpp)

add_executable(main
        src/main.cpp)

add_executable(test_emap
        src/test_emap.cpp)
        
add_executable(test_agg
        src/test_agg.cpp)

add_executable(qx
        src/qx.cpp)

add_executable(eq_bench
        src/eq_bench.cpp)

# packages

find_package(SEAL CONFIG REQUIRED)

find_package(MPI REQUIRED)
add_definitions(-DOMPI_SKIP_MPICXX)

include_directories(SYSTEM ${MPI_INCLUDE_PATH})

# links
target_link_libraries(keygen SEAL::seal)

target_link_libraries(main SEAL::seal)
target_link_libraries(main ${MPI_C_LIBRARIES})

target_link_libraries(test_emap SEAL::seal)
target_link_libraries(test_emap ${MPI_C_LIBRARIES})

target_link_libraries(test_agg SEAL::seal)
target_link_libraries(test_agg ${MPI_C_LIBRARIES})


target_link_libraries(qx SEAL::seal)
target_link_libraries(qx ${MPI_C_LIBRARIES})

target_link_libraries(eq_bench SEAL::seal)
target_link_libraries(eq_bench ${MPI_C_LIBRARIES})
