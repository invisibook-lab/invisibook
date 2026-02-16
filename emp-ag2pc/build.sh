#!/bin/bash
# 构建脚本

set -e

BUILD_DIR="build"
mkdir -p $BUILD_DIR

cd $BUILD_DIR

# 运行 CMake
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local

# 编译
make -j$(nproc)

# 安装（可选）
# sudo make install

echo "构建完成！库文件在 $BUILD_DIR/lib/ 目录下"
