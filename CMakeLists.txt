# 最低要求的 CMake 版本
cmake_minimum_required(VERSION 3.10)
# 项目名称（建议与目录名一致）
project(dpdk-network-app LANGUAGES C)

# --------------------------
# 构建输出路径配置
# --------------------------
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# --------------------------
# 编译选项与标准
# --------------------------
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-O3 -march=native)
add_definitions(-DALLOW_EXPERIMENTAL_API)

# --------------------------
# DPDK 依赖配置
# --------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(RTE REQUIRED libdpdk)

# --------------------------
# 动态收集源文件（关键修正）
# --------------------------
# 递归收集 src 目录下所有 .c 文件（包括子目录）
file(GLOB_RECURSE SOURCES 
    "src/*.c" 
    "src/network/*.c" 
    "src/protocol/*.c" 
    "src/app/*.c" 
    "src/utils/*.c"
)

add_executable(dpdk-network-app ${SOURCES})  # 确保 SOURCES 非空

# --------------------------
# 包含目录配置
# --------------------------
target_include_directories(dpdk-network-app PRIVATE 
    ${RTE_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include
)

# --------------------------
# 链接配置
# --------------------------
target_link_libraries(dpdk-network-app PRIVATE ${RTE_LIBRARIES} pthread)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed")

# 自动生成构建目录
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR})
message(STATUS "Build directory created at: ${CMAKE_BINARY_DIR}")