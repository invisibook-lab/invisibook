# emp-ag2pc FFI 绑定

这个目录包含 emp-ag2pc 的 C++ 实现和 Rust FFI 接口。

## 目录结构

```
emp-ag2pc/
├── include/           # C 头文件
│   └── emp_ag2pc_ffi.h
├── src/              # C++ 实现
│   └── emp_ag2pc_ffi.cpp
├── CMakeLists.txt    # CMake 构建配置
├── build.sh          # 构建脚本
└── README.md         # 本文件
```

## 前置要求

1. **安装 emp-toolkit**：
   ```bash
   git clone https://github.com/emp-toolkit/emp-tool.git
   cd emp-tool
   cmake .
   make
   sudo make install
   ```

2. **安装 emp-ag2pc**：
   ```bash
   git clone https://github.com/emp-toolkit/emp-ag2pc.git
   cd emp-ag2pc
   cmake .
   make
   sudo make install
   ```

3. **系统依赖**：
   - CMake >= 3.10
   - C++17 编译器
   - OpenSSL
   - GMP

## 构建

### 方法 1：使用构建脚本

```bash
cd emp-ag2pc
chmod +x build.sh
./build.sh
```

### 方法 2：使用 CMake

```bash
cd emp-ag2pc
mkdir build
cd build
cmake ..
make
```

构建完成后，库文件会在 `build/lib/` 目录下。

## Rust 使用

在 Rust 项目中使用：

```rust
use invisibook_client::{Ag2pc, NetIO, Party};

// Alice 端
let netio = NetIO::create_server(12345)?;
let mut ag2pc = Ag2pc::new(&netio, Party::Alice)?;
ag2pc.garble(12345)?;
let result = ag2pc.get_result()?;

// Bob 端
let netio = NetIO::create_client("127.0.0.1", 12345)?;
let mut ag2pc = Ag2pc::new(&netio, Party::Bob)?;
ag2pc.eval(67890)?;
let result = ag2pc.get_result()?;
```

## API 说明

### C FFI 接口

所有函数都在 `include/emp_ag2pc_ffi.h` 中定义。

主要函数：
- `netio_create_server(port)` - 创建服务器端连接
- `netio_create_client(ip, port)` - 创建客户端连接
- `emp_ag2pc_create(io, party)` - 创建 AG2PC 实例
- `emp_ag2pc_garble(handle, input_a)` - 执行混淆协议（Alice）
- `emp_ag2pc_eval(handle, input_b)` - 执行评估协议（Bob）
- `emp_ag2pc_get_result(handle, result)` - 获取比较结果

### Rust 接口

Rust 接口在 `client/src/emp_ag2pc.rs` 中定义，提供了类型安全的包装。

## 示例

运行示例代码：

```bash
# 终端 1：运行 Alice
cargo run --example alice -- 12345

# 终端 2：运行 Bob
cargo run --example bob -- 67890 127.0.0.1 12345
```

## 注意事项

1. **网络连接**：确保防火墙允许指定端口的连接
2. **库路径**：如果库安装在非标准路径，需要设置 `LD_LIBRARY_PATH`
3. **错误处理**：所有函数都可能失败，请检查返回值
4. **线程安全**：当前实现不是线程安全的，不要在多个线程间共享同一个实例

## 故障排除

### 链接错误

如果遇到链接错误，检查：
1. emp-tool 和 emp-ag2pc 是否正确安装
2. 库路径是否正确设置
3. CMakeLists.txt 中的库名称是否正确

### 运行时错误

如果运行时出错：
1. 检查网络连接
2. 确保端口未被占用
3. 查看错误信息（使用 `emp_ag2pc_get_last_error()`）
