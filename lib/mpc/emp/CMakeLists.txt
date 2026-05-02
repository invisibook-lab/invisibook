cmake_minimum_required(VERSION 3.12)
project(invisibook_2pc)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find emp dependencies (installed by scripts/install_deps.sh)
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/third_party/install")

find_package(emp-tool REQUIRED)
find_package(emp-ot REQUIRED)
find_package(emp-ag2pc REQUIRED)

add_executable(sha256_compare src/main.cpp)

target_include_directories(sha256_compare PRIVATE
    ${EMP-AG2PC_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(sha256_compare
    ${EMP-AG2PC_LIBRARIES}
)
