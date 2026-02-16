// 构建脚本：编译 emp-ag2pc C++ 库

use std::env;
use std::path::PathBuf;

fn main() {
    // 告诉 Cargo 如果这些文件改变，重新运行构建脚本
    println!("cargo:rerun-if-changed=../emp-ag2pc/src/emp_ag2pc_ffi.cpp");
    println!("cargo:rerun-if-changed=../emp-ag2pc/include/emp_ag2pc_ffi.h");
    
    // 获取项目根目录
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let emp_ag2pc_dir = manifest_dir.parent().unwrap().join("emp-ag2pc");
    
    // 设置库搜索路径
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native={}/build/lib", emp_ag2pc_dir.display());
    
    // 链接库
    println!("cargo:rustc-link-lib=emp_ag2pc_ffi");
    println!("cargo:rustc-link-lib=emp-ag2pc");
    println!("cargo:rustc-link-lib=emp-tool");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=pthread");
    
    // 编译 C++ 代码
    let mut build = cc::Build::new();
    
    build
        .cpp(true)
        .std("c++17")
        .file(emp_ag2pc_dir.join("src/emp_ag2pc_ffi.cpp"))
        .include(emp_ag2pc_dir.join("include"))
        .include("/usr/local/include")
        .include("/usr/include")
        .flag("-std=c++17")
        .compile("emp_ag2pc_ffi");
    
    // 输出库路径
    println!("cargo:rustc-link-search=native={}", env::var("OUT_DIR").unwrap());
}
