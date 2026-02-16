//! Alice 端示例：作为 Garbler 比较两个隐私数字
//! 
//! 运行方式：
//! cargo run --example alice -- 12345
//! 
//! 其中 12345 是 Alice 的隐私数字

use invisibook_client::{Ag2pc, NetIO, Party, Ag2pcError};
use std::env;

fn main() -> Result<(), Ag2pcError> {
    // 解析命令行参数
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("用法: {} <alice的数字> [端口]", args[0]);
        eprintln!("示例: {} 12345 12345", args[0]);
        std::process::exit(1);
    }
    
    let input_a: u64 = args[1]
        .parse()
        .expect("无效的数字，请输入有效的 u64 整数");
    
    let port: u16 = args.get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(12345);
    
    println!("=== Alice (Garbler) ===");
    println!("我的数字: {}", input_a);
    println!("监听端口: {}", port);
    println!();
    
    // 创建网络连接（作为服务器）
    println!("正在创建服务器连接...");
    let netio = NetIO::create_server(port)
        .map_err(|e| Ag2pcError::Network(e))?;
    println!("服务器已启动，等待 Bob 连接...");
    
    // 创建 AG2PC 实例
    println!("正在初始化 AG2PC 协议...");
    let mut ag2pc = Ag2pc::new(&netio, Party::Alice)
        .map_err(|e| Ag2pcError::Init(e))?;
    
    // 执行混淆电路协议
    println!("正在执行混淆电路协议...");
    ag2pc.garble(input_a)?;
    println!("混淆表已生成并发送给 Bob");
    
    // 获取结果
    println!("正在获取比较结果...");
    let result = ag2pc.get_result()?;
    
    println!();
    println!("=== 比较结果 ===");
    if result {
        println!("我的数字 > Bob 的数字");
    } else {
        println!("我的数字 <= Bob 的数字");
    }
    
    Ok(())
}
