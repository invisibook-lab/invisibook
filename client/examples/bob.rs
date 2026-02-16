//! Bob 端示例：作为 Evaluator 比较两个隐私数字
//! 
//! 运行方式：
//! cargo run --example bob -- 67890 127.0.0.1 12345
//! 
//! 其中：
//! - 67890 是 Bob 的隐私数字
//! - 127.0.0.1 是 Alice 的 IP 地址
//! - 12345 是端口号

use invisibook_client::{Ag2pc, NetIO, Party, Ag2pcError};
use std::env;

fn main() -> Result<(), Ag2pcError> {
    // 解析命令行参数
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("用法: {} <bob的数字> <alice的IP> <端口>", args[0]);
        eprintln!("示例: {} 67890 127.0.0.1 12345", args[0]);
        std::process::exit(1);
    }
    
    let input_b: u64 = args[1]
        .parse()
        .expect("无效的数字，请输入有效的 u64 整数");
    
    let server_ip = &args[2];
    let port: u16 = args[3]
        .parse()
        .expect("无效的端口号");
    
    println!("=== Bob (Evaluator) ===");
    println!("我的数字: {}", input_b);
    println!("连接到: {}:{}", server_ip, port);
    println!();
    
    // 创建网络连接（作为客户端）
    println!("正在连接到 Alice...");
    let netio = NetIO::create_client(server_ip, port)
        .map_err(|e| Ag2pcError::Network(e))?;
    println!("已连接到 Alice");
    
    // 创建 AG2PC 实例
    println!("正在初始化 AG2PC 协议...");
    let mut ag2pc = Ag2pc::new(&netio, Party::Bob)
        .map_err(|e| Ag2pcError::Init(e))?;
    
    // 执行混淆电路协议
    println!("正在接收混淆表...");
    println!("正在执行 OT 协议获取输入标签...");
    ag2pc.eval(input_b)?;
    println!("电路评估完成");
    
    // 获取结果
    println!("正在获取比较结果...");
    let result = ag2pc.get_result()?;
    
    println!();
    println!("=== 比较结果 ===");
    if result {
        println!("Alice 的数字 > 我的数字");
    } else {
        println!("Alice 的数字 <= 我的数字");
    }
    
    Ok(())
}
