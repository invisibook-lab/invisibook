# MPC 代码结构分析

`client/mpc/` 目录下的代码可以分为两大块：

## 一、MPC Circuit（电路逻辑）部分

这部分代码定义了**要执行的 MPC 计算逻辑**，使用 Summon 框架编写，会被编译成混淆电路。

### 核心文件

#### 1. **电路定义文件** (`src/circuit/`)

- **`src/circuit/main.ts`** - 电路主入口
  - 定义 MPC 协议的输入输出
  - 调用 `isEqual` 和 `isLarger` 函数
  - 输出结果：0（相等）、1（alice 更大）、2（bob 更大）
  ```typescript
  export default (io: Summon.IO) => {
    const a = io.input('alice', 'a', summon.number());
    const b = io.input('bob', 'b', summon.number());
    // ... 比较逻辑
    io.outputPublic('main', result);
  };
  ```

- **`src/circuit/isLarger.ts`** - 比较函数（电路逻辑）
  - 定义 `a > b` 的比较逻辑
  ```typescript
  export default function isLarger(a: number, b: number): boolean {
    return a > b;
  }
  ```

- **`src/circuit/isEqual.ts`** - 相等比较函数（电路逻辑）
  - 定义 `a === b` 的比较逻辑
  ```typescript
  export default function isEqual(a: number, b: number): boolean {
    return a === b;
  }
  ```

- **`src/circuit/summon.d.ts`** - Summon 类型定义
  - TypeScript 类型声明，用于电路代码的类型检查

#### 2. **电路编译和协议生成**

- **`src/generateProtocol.ts`** - 生成 MPC 协议
  - 使用 `summon-ts` 编译电路代码
  - 创建 `Protocol` 实例（使用 `EmpWasmEngine`）
  - 将 TypeScript 电路代码转换为可执行的 MPC 协议
  ```typescript
  const { circuit } = summon.compile({
    path: 'circuit/main.ts',
    boolifyWidth: 16,
    files: await getCircuitFiles(),
  });
  return new Protocol(circuit, new EmpWasmEngine());
  ```

- **`src/getCircuitFiles.ts`** - 获取电路文件
  - 动态加载 `circuit/` 目录下的所有 `.ts` 文件
  - 用于电路编译时提供所有相关文件
  ```typescript
  const files = import.meta.glob('./circuit/**/*.ts', {
    query: '?raw',
    import: 'default',
  });
  ```

### 特点

- **纯函数式**：电路代码是纯函数，不依赖外部状态
- **编译时处理**：在运行时被编译成混淆电路
- **类型安全**：使用 TypeScript 和 Summon 类型系统
- **可组合**：可以拆分成多个文件（如 `isLarger.ts`, `isEqual.ts`）

---

## 二、前端 UI（用户界面）部分

这部分代码负责**用户交互、UI 展示和 MPC 协议的执行**。

### 核心文件

#### 1. **UI 结构文件**

- **`index.html`** - HTML 页面结构
  - 定义 5 个步骤的 UI：
    - Step 1: 欢迎页面（Host/Join 按钮）
    - Step 2: 连接码显示/输入
    - Step 3: 数字输入
    - Step 4: 等待计算（进度显示）
    - Step 5: 结果显示
  - 包含所有 DOM 元素（按钮、输入框、文本等）

- **`src/styles.css`** - 样式文件
  - 页面样式定义
  - 按钮、容器、动画等样式

#### 2. **前端逻辑文件**

- **`src/main.ts`** - 前端入口文件
  - DOM 元素获取和事件绑定
  - 处理用户交互：
    - `handleHost()` - 处理 Host 按钮点击
    - `handleJoin()` - 处理 Join 按钮点击
    - `handleJoinSubmit()` - 处理连接码提交
    - `handleSubmitNumber()` - 处理数字提交
  - 控制步骤切换（显示/隐藏不同的 step）
  - 更新 UI 状态（进度、结果等）

- **`src/App.ts`** - 核心应用类
  - **连接管理**：
    - `generateJoiningCode()` - 生成 P2P 连接码
    - `connect()` - 建立 WebRTC P2P 连接
  - **MPC 执行**：
    - `mpcLargest()` - 执行 MPC 协议比较数字
    - 管理消息队列和协议会话
    - 处理进度回调
  - **通信管理**：
    - 使用 `RtcPairSocket` 进行 P2P 通信
    - 使用 `AsyncQueue` 管理消息

#### 3. **工具文件**

- **`src/AsyncQueue.ts`** - 异步消息队列
  - 用于 MPC 协议消息的异步处理
  - 支持消息推送、拉取和流式处理
  - 确保消息不丢失（在协议开始前收到的消息会被缓存）

- **`src/assert.ts`** - 断言工具
  - 简单的断言函数，用于运行时检查

### 配置文件

- **`package.json`** - 依赖和脚本配置
  - 前端依赖：`mpc-framework`, `emp-wasm-engine`, `summon-ts`, `rtc-pair-socket`
  - 构建工具：Vite
  - 开发脚本：`npm run dev`, `npm run build`

- **`vite.config.ts`** - Vite 构建配置
- **`tsconfig.json`** - TypeScript 配置
- **`tsconfig.node.json`** - Node.js TypeScript 配置

### 特点

- **交互式 UI**：多步骤的用户界面
- **P2P 通信**：使用 WebRTC 进行点对点连接
- **实时反馈**：进度显示、状态更新
- **浏览器端执行**：MPC 协议在浏览器中运行（使用 WebAssembly）

---

## 工作流程

```
用户打开页面 (index.html)
    ↓
前端 UI 交互 (main.ts)
    ↓
建立 P2P 连接 (App.ts)
    ↓
编译电路代码 (generateProtocol.ts)
    ↓
执行 MPC 协议 (App.mpcLargest)
    ↓
使用电路逻辑 (circuit/main.ts)
    ↓
显示结果 (main.ts)
```

## 总结

| 分类 | 文件 | 职责 |
|------|------|------|
| **MPC Circuit** | `circuit/*.ts`<br>`generateProtocol.ts`<br>`getCircuitFiles.ts` | 定义 MPC 计算逻辑<br>编译电路<br>加载电路文件 |
| **前端 UI** | `index.html`<br>`main.ts`<br>`App.ts`<br>`styles.css`<br>`AsyncQueue.ts`<br>`assert.ts` | UI 结构<br>用户交互<br>应用逻辑<br>样式<br>工具函数 |

**关键区别**：
- **Circuit 部分**：定义"计算什么"（纯逻辑，无 UI）
- **前端部分**：定义"如何交互"（UI、连接、执行）
