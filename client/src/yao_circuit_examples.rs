//! Rust 实现的 Yao 混淆电路库示例
//! 
//! 以下是几个主要的 Rust 混淆电路库：

// ============================================================================
// 1. fancy-garbling - 最流行的 Rust 混淆电路库
// ============================================================================
// GitHub: https://github.com/GaloisInc/fancy-garbling
// Crates.io: https://crates.io/crates/fancy-garbling
// 
// 使用示例：
/*
use fancy_garbling::*;

// 创建混淆电路评估器
let mut gb = Garbler::new(&mut rng);
let mut ev = Evaluator::new();

// 定义电路（例如：比较两个数的大小）
let a = gb.encode(5, 8);  // 8位编码
let b = gb.encode(3, 8);
let result = gb.gt(&a, &b);  // 5 > 3

// 生成混淆表
let tables = gb.garble();
let output = ev.eval(&tables, &[a, b]);

// 解码结果
let decoded = gb.decode(&output);
*/

// ============================================================================
// 2. scuttlebutt - 安全多方计算库（包含混淆电路）
// ============================================================================
// GitHub: https://github.com/GaloisInc/scuttlebutt
// Crates.io: https://crates.io/crates/scuttlebutt
//
// 使用示例：
/*
use scuttlebutt::{AesRng, Channel, SymChannel};
use scuttlebutt::cointoss::SharedRng;
use scuttlebutt::garbled::GarbledCircuit;

// 创建通道和随机数生成器
let mut channel = SymChannel::new();
let mut rng = AesRng::new();

// 创建混淆电路
let mut gc = GarbledCircuit::new(&mut channel, &mut rng);

// 执行混淆电路计算
// ...
*/

// ============================================================================
// 3. ocelot - 安全多方计算框架
// ============================================================================
// GitHub: https://github.com/ladnir/ocelot
// Crates.io: https://crates.io/crates/ocelot
//
// 使用示例：
/*
use ocelot::ot::AlszReceiver as OtReceiver;
use ocelot::ot::AlszSender as OtSender;
use ocelot::garbling::*;

// 创建混淆电路生成器和评估器
let mut gb = Garbler::new();
let mut ev = Evaluator::new();

// 执行混淆电路协议
// ...
*/

// ============================================================================
// 推荐的库选择：
// ============================================================================
// 
// 1. **fancy-garbling** - 最适合学习和研究
//    - 文档完善
//    - API 设计清晰
//    - 支持多种电路操作
//    - 活跃维护
//
// 2. **scuttlebutt** - 适合生产环境
//    - 性能优化
//    - 包含完整的 MPC 协议栈
//    - 由 Galois 公司维护
//
// 3. **ocelot** - 适合高级应用
//    - 功能全面
//    - 支持多种 MPC 协议
//
// ============================================================================
// 在 Cargo.toml 中添加依赖：
// ============================================================================
//
// [dependencies]
// fancy-garbling = "0.5"  # 或最新版本
// scuttlebutt = "0.3"     # 或最新版本
// ocelot = "0.3"          # 或最新版本

// ============================================================================
// 完整示例：使用 fancy-garbling 实现简单的比较电路
// ============================================================================
/*
use fancy_garbling::*;
use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();
    
    // 创建混淆电路生成器
    let mut gb = Garbler::new(&mut rng);
    
    // 输入：两个 8 位数字
    let a = gb.encode(10u64, 8);
    let b = gb.encode(5u64, 8);
    
    // 构建电路：a > b
    let result = gb.gt(&a, &b);
    
    // 生成混淆表
    let tables = gb.garble();
    
    // 创建评估器
    let mut ev = Evaluator::new();
    
    // 评估电路
    let output = ev.eval(&tables, &[a, b]);
    
    // 解码结果
    let decoded = gb.decode(&output);
    
    println!("10 > 5 = {}", decoded);
}
*/
