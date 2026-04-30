# Invisibook 测试验收指南

## 环境准备

### 编译

```bash
# 编译链
cd chain
go build -o invisibook .

# 编译 Desktop App
cd app/desktop
cargo build --release
```

### 测试账号

| 角色 | 助记词 | 初始余额 |
|------|--------|---------|
| Alice | `test test test test test test test test test test test junk` | 1000 ETH, 500000 USDT |

Cash 文件：`chain/cfg/tests/alice_plain_cash.json`

---

## 测试步骤

### 1. 启动链

```bash
cd chain
rm -rf data/   
rm ~/.invisibook/cash.json
./invisibook
```

等待看到 `start a new block` 后继续。

### 2. 启动 Desktop 并导入账户

1. 启动 Desktop App
2. 点击右上角 **Import Key**
3. 输入助记词：`test test test test test test test test test test test junk`
4. 拖入 `chain/cfg/tests/alice_plain_cash.json`
5. 点击 **Import**

**验证**：右上角显示地址，右侧面板显示 `ETH: 1000` 和 `USDT: 500000`

### 3. 提交卖单

1. 右侧面板选择 **Sell**
2. 交易对选 **ETH / USDT**
3. Price 输入 `3500`，Amount 输入 `100`
4. 点击 **Sell ETH**

**验证**：等待约 3 秒后，Order Book 出现一笔订单，状态为 **Pending**

### 4. 提交买单（触发撮合）

1. 切换到 **Buy**
2. 交易对 **ETH / USDT**，Price 输入 `3500`，Amount 输入 `100`
3. 点击 **Buy ETH**

**验证**：等待约 3 秒后，Order Book 中两笔订单状态都变为 **Matched**

---

## 撮合规则

| 优先级 | 规则 | 说明 |
|--------|------|------|
| 1 | 价格优先 | Buy 方选最低卖价，Sell 方选最高买价 |
| 2 | 区块高度优先 | 同价格时，更早上链的订单优先 |
| 3 | 手续费优先 | 同区块时，手续费更高的订单优先 |

价格兼容条件：Buy price >= Sell price（例：Buy@3500 + Sell@3500 可匹配）

---

## 常见问题

| 现象 | 解决方式 |
|------|---------|
| Order Book 没有变化 | 确认链进程正在运行 |
| 两笔订单都是 Pending | 确认交易对一致，且 Buy price >= Sell price |
| 提示余额不足 | 检查 Active Token 余额 |
| 导入后没有余额 | 重新 Import Key 并拖入 cash.json 文件 |
