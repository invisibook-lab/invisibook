# emp-ag2pc 使用指南

## 快速开始

### 1. 安装依赖

首先需要安装 emp-toolkit 和 emp-ag2pc：

```bash
# 安装 emp-tool
git clone https://github.com/emp-toolkit/emp-tool.git
cd emp-tool
cmake .
make -j$(nproc)
sudo make install

# 安装 emp-ag2pc
git clone https://github.com/emp-toolkit/emp-ag2pc.git
cd emp-ag2pc
cmake .
make -j$(nproc)
sudo make install
```

### 2. 构建 FFI 库

```bash
cd emp-ag2pc
./build.sh
```

### 3. 在 Rust 中使用

#### 方法 A：使用示例代码

```bash
# 终端 1：运行 Alice（Garbler）
cargo run --example alice -- 12345

# 终端 2：运行 Bob（Evaluator）
cargo run --example bob -- 67890 127.0.0.1 12345
```

#### 方法 B：在自己的代码中使用

```rust
use invisibook_client::{Ag2pc, NetIO, Party, Ag2pcError};

// Alice 端代码
fn alice_compare(input_a: u64, port: u16) -> Result<bool, Ag2pcError> {
    let netio = NetIO::create_server(port)?;
    let mut ag2pc = Ag2pc::new(&netio, Party::Alice)?;
    ag2pc.garble(input_a)?;
    ag2pc.get_result()
}

// Bob 端代码
fn bob_compare(input_b: u64, server_ip: &str, port: u16) -> Result<bool, Ag2pcError> {
    let netio = NetIO::create_client(server_ip, port)?;
    let mut ag2pc = Ag2pc::new(&netio, Party::Bob)?;
    ag2pc.eval(input_b)?;
    ag2pc.get_result()
}
```

## API 文档

### NetIO

网络连接句柄，用于在两台机器之间建立通信。

```rust
// 创建服务器（Alice）
let netio = NetIO::create_server(12345)?;

// 创建客户端（Bob）
let netio = NetIO::create_client("192.168.1.100", 12345)?;
```

### Ag2pc

AG2PC 协议实例，用于执行混淆电路协议。

```rust
// 创建实例
let mut ag2pc = Ag2pc::new(&netio, Party::Alice)?;

// Alice 执行混淆
ag2pc.garble(12345)?;

// Bob 执行评估
ag2pc.eval(67890)?;

// 获取结果（true 表示 input_a > input_b）
let result = ag2pc.get_result()?;
```

### Party

协议参与方枚举：

- `Party::Alice` - 混淆电路生成器（Garbler）
- `Party::Bob` - 混淆电路评估器（Evaluator）

### Ag2pcError

错误类型：

- `Ag2pcError::Init(String)` - 初始化错误
- `Ag2pcError::Network(String)` - 网络错误
- `Ag2pcError::Protocol(String)` - 协议执行错误

## 使用场景

### 场景：比较两个隐私数字

假设：
- Alice 有数字 `a = 12345`
- Bob 有数字 `b = 67890`
- 双方想知道 `a > b` 的结果，但不想泄露自己的数字

**解决方案**：

1. Alice 作为 Garbler，生成混淆电路
2. Bob 作为 Evaluator，评估混淆电路
3. 双方得到比较结果，但不知道对方的输入

## 性能指标

- **混淆表大小**：约 7-10 KB（64 位比较）
- **总通信量**：约 10-15 KB
- **计算时间**：通常 < 100ms（不含网络延迟）

## 故障排除

### 链接错误

如果遇到链接错误：

```bash
# 检查库是否安装
ldconfig -p | grep emp

# 设置库路径
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

### 网络连接失败

1. 检查防火墙设置
2. 确保端口未被占用
3. 验证 IP 地址和端口号

### 编译错误

确保：
1. emp-tool 和 emp-ag2pc 已正确安装
2. CMake 版本 >= 3.10
3. C++17 编译器可用

## 注意事项

1. **线程安全**：当前实现不是线程安全的
2. **错误处理**：所有操作都可能失败，请检查返回值
3. **资源管理**：NetIO 和 Ag2pc 会在 Drop 时自动清理资源
4. **网络延迟**：实际性能取决于网络延迟
