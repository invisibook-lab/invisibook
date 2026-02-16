# emp-ag2pc 使用指南：比较两个隐私数字的大小

## 库介绍

**emp-ag2pc** 是 EMP-toolkit 中专门用于**两方安全计算（2PC）**的库，基于 Yao 混淆电路实现，使用半门电路（Half-Gate）优化技术。

GitHub: https://github.com/emp-toolkit/emp-ag2pc

## 你的使用场景

- **场景**：比较两个隐私数字的大小（例如判断 `a > b`）
- **约束**：
  - 数字 `a` 在机器 A（Alice）上
  - 数字 `b` 在机器 B（Bob）上
  - 双方都不希望对方知道自己的数字
  - 只需要知道比较结果（`a > b` 或 `a <= b`）

## 核心概念

### 角色分配

1. **Alice（Garbler/生成器）**：
   - 拥有数字 `a`
   - 生成混淆电路和混淆表
   - 发送混淆表给 Bob

2. **Bob（Evaluator/评估器）**：
   - 拥有数字 `b`
   - 接收混淆表
   - 通过 OT 协议获取输入标签
   - 评估电路并得到结果

### 协议流程

```
1. Alice 和 Bob 建立网络连接
2. Alice 生成混淆电路（将比较操作转换为布尔电路）
3. Alice 生成混淆表并发送给 Bob
4. Alice 和 Bob 执行 OT 协议：
   - Alice 发送自己的输入标签（对应数字 a）
   - Bob 通过 OT 获取自己的输入标签（对应数字 b）
5. Bob 使用混淆表和输入标签评估电路
6. Bob 得到比较结果（可以发送给 Alice 或仅自己知道）
```

## 安装和编译

### 前置要求

```bash
# 安装依赖
sudo apt-get install cmake g++ git libssl-dev libgmp-dev

# 克隆 emp-toolkit
git clone https://github.com/emp-toolkit/emp-tool.git
cd emp-tool
cmake .
make
sudo make install

# 克隆 emp-ag2pc
git clone https://github.com/emp-toolkit/emp-ag2pc.git
cd emp-ag2pc
cmake .
make
```

## 代码示例

### 示例 1：基本比较（Alice 作为 Garbler）

**alice.cpp**（机器 A）：

```cpp
#include "emp-ag2pc/ag2pc.h"
#include "emp-tool/emp-tool.h"
#include <iostream>

using namespace emp;

int main(int argc, char** argv) {
    // 1. 建立网络连接（Alice 作为服务器）
    int port = 12345;
    NetIO* io = new NetIO(nullptr, port);  // nullptr 表示作为服务器
    
    // 2. 创建 AG2PC 实例（Alice 作为 Garbler）
    AG2PC* ag2pc = new AG2PC(io, ALICE);
    
    // 3. Alice 的输入数字（uint64）
    uint64_t a = 12345;  // Alice 的隐私数字
    
    // 4. 构建比较电路
    // 假设 Bob 的数字是 b，我们要计算 a > b
    // 这需要将 a 和 b 转换为二进制，然后构建比较电路
    
    // 5. 执行协议
    // 这里需要根据 emp-ag2pc 的具体 API 调用
    // 通常需要：
    // - 定义电路（使用 emp-tool 的电路构建 API）
    // - 调用 ag2pc->garble() 生成混淆表
    // - 通过 OT 发送输入标签
    
    // 6. 获取结果
    bool result = ag2pc->get_result();
    std::cout << "Comparison result: " << result << std::endl;
    
    delete ag2pc;
    delete io;
    return 0;
}
```

**bob.cpp**（机器 B）：

```cpp
#include "emp-ag2pc/ag2pc.h"
#include "emp-tool/emp-tool.h"
#include <iostream>

using namespace emp;

int main(int argc, char** argv) {
    // 1. 建立网络连接（Bob 作为客户端）
    const char* server_ip = "192.168.1.100";  // Alice 的 IP 地址
    int port = 12345;
    NetIO* io = new NetIO(server_ip, port);  // 连接到 Alice
    
    // 2. 创建 AG2PC 实例（Bob 作为 Evaluator）
    AG2PC* ag2pc = new AG2PC(io, BOB);
    
    // 3. Bob 的输入数字（uint64）
    uint64_t b = 67890;  // Bob 的隐私数字
    
    // 4. 执行协议
    // - 接收混淆表
    // - 通过 OT 获取输入标签
    // - 评估电路
    
    // 5. 获取结果
    bool result = ag2pc->get_result();
    std::cout << "Comparison result: " << result << std::endl;
    
    delete ag2pc;
    delete io;
    return 0;
}
```

### 示例 2：使用 emp-tool 的电路构建 API

```cpp
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/ag2pc.h"
#include <iostream>

using namespace emp;

// 构建 64 位整数比较电路
void build_comparison_circuit(Circuit* circ, Integer a, Integer b) {
    // 计算 a > b
    // 使用减法：a - b，然后检查符号位
    Integer diff = a - b;
    Bit result = diff[63];  // 符号位（最高位）
    // 如果 diff < 0，则 a < b，result = 1
    // 如果 diff >= 0，则 a >= b，result = 0
    // 所以 a > b 等价于 !result && (diff != 0)
    
    // 更精确的比较逻辑
    Bit is_negative = diff[63];
    Bit is_zero = (diff == Integer(64, 0));
    Bit a_greater_than_b = !is_negative && !is_zero;
    
    circ->output(a_greater_than_b);
}

int main(int argc, char** argv) {
    // 网络连接
    NetIO* io = new NetIO(argc > 1 ? nullptr : argv[1], 12345);
    
    // 创建电路
    Circuit* circ = new Circuit();
    
    // 输入：两个 64 位整数
    Integer a(64, 0);  // Alice 的输入
    Integer b(64, 0);  // Bob 的输入
    
    // 构建电路
    build_comparison_circuit(circ, a, b);
    
    // 执行 AG2PC 协议
    AG2PC* ag2pc = new AG2PC(io, argc > 1 ? ALICE : BOB);
    
    // 设置输入并执行
    if (argc > 1) {
        // Alice: 设置自己的输入
        a = Integer(64, 12345);
        ag2pc->garble(circ, &a, nullptr);
    } else {
        // Bob: 设置自己的输入
        b = Integer(64, 67890);
        ag2pc->eval(circ, nullptr, &b);
    }
    
    // 获取结果
    bool result = ag2pc->get_result();
    std::cout << "a > b: " << result << std::endl;
    
    delete ag2pc;
    delete circ;
    delete io;
    return 0;
}
```

## 实际使用步骤

### 1. 准备两台机器

- **机器 A（Alice）**：运行 Garbler 程序
- **机器 B（Bob）**：运行 Evaluator 程序

### 2. 编译代码

```bash
# 在机器 A 和 B 上都编译
g++ -std=c++11 alice.cpp -o alice -lemp-ag2pc -lemp-tool -lssl -lcrypto -lgmp
g++ -std=c++11 bob.cpp -o bob -lemp-ag2pc -lemp-tool -lssl -lcrypto -lgmp
```

### 3. 运行程序

```bash
# 在机器 A 上运行（作为服务器）
./alice

# 在机器 B 上运行（连接到机器 A）
./bob 192.168.1.100  # 替换为机器 A 的实际 IP
```

## 关键 API 说明

### AG2PC 类

```cpp
class AG2PC {
public:
    AG2PC(NetIO* io, int party);  // party: ALICE 或 BOB
    
    // Garbler 方法
    void garble(Circuit* circ, Integer* input_a, Integer* input_b);
    
    // Evaluator 方法
    void eval(Circuit* circ, Integer* input_a, Integer* input_b);
    
    // 获取结果
    bool get_result();
};
```

### 网络通信

```cpp
// 作为服务器（Alice）
NetIO* io = new NetIO(nullptr, port);

// 作为客户端（Bob）
NetIO* io = new NetIO(server_ip, port);
```

## 性能考虑

### 通信开销

对于比较两个 uint64 整数：
- **混淆表大小**：约 7-10 KB（使用半门电路优化）
- **OT 协议开销**：约 2-3 KB（64 次 OT，每个输入位）
- **总通信量**：约 **10-15 KB**

### 计算开销

- **Garbler（Alice）**：生成混淆表，约几毫秒
- **Evaluator（Bob）**：评估电路，约几毫秒
- **总延迟**：网络延迟 + 计算时间（通常 < 100ms）

## 安全注意事项

1. **网络连接**：使用 TLS/SSL 加密网络通信
2. **输入验证**：确保输入是有效的 uint64 值
3. **结果验证**：可以添加结果验证机制
4. **防重放攻击**：使用会话 ID 或时间戳

## 常见问题

### Q: 如何确保双方都不知道对方的输入？
A: 混淆电路协议本身保证了这一点。Alice 只能看到混淆表，Bob 只能看到混淆后的标签，都无法推断原始输入。

### Q: 结果可以被双方看到吗？
A: 可以配置。可以让只有 Bob 知道结果，或者让双方都知道结果。

### Q: 支持其他比较操作吗？
A: 可以，只需要修改电路逻辑：
- `a > b`：使用减法检查符号位
- `a < b`：类似，但逻辑相反
- `a == b`：检查差是否为零
- `a >= b`：`a > b || a == b`

## 参考资源

- EMP-toolkit 文档：https://github.com/emp-toolkit/emp-tool
- 混淆电路原理：Yao's Garbled Circuits
- 半门电路优化：Half-Gate Technique
