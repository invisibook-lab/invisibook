cmake_minimum_required(VERSION 3.10)
project(emp_ag2pc_ffi)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找依赖库
find_package(PkgConfig REQUIRED)

# 查找 emp-tool 和 emp-ag2pc
# 假设这些库已经安装到系统路径
# 如果没有安装，需要设置 EMP_TOOL_DIR 和 EMP_AG2PC_DIR

# 包含目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    /usr/local/include
    /usr/include
)

# 源文件
set(SOURCES
    src/emp_ag2pc_ffi.cpp
)

# 创建共享库
add_library(emp_ag2pc_ffi SHARED ${SOURCES})

# 链接库
target_link_libraries(emp_ag2pc_ffi
    emp-ag2pc
    emp-tool
    ssl
    crypto
    gmp
    pthread
)

# 安装规则
install(TARGETS emp_ag2pc_ffi
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES include/emp_ag2pc_ffi.h
    DESTINATION include
)

# 设置输出目录
set_target_properties(emp_ag2pc_ffi PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)
