//! emp-ag2pc Rust FFI 绑定
//! 
//! 这个模块提供了对 emp-ag2pc C++ 库的 Rust 接口

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// 从 C 头文件导入的常量
pub const ALICE: c_int = 1;
pub const BOB: c_int = 2;

pub const EMP_AG2PC_SUCCESS: c_int = 0;
pub const EMP_AG2PC_ERROR_INIT: c_int = -1;
pub const EMP_AG2PC_ERROR_NETWORK: c_int = -2;
pub const EMP_AG2PC_ERROR_PROTOCOL: c_int = -3;

// 链接到 C++ 库
#[link(name = "emp_ag2pc_ffi")]
extern "C" {
    // 网络连接函数
    fn netio_create_server(port: c_int) -> *mut c_void;
    fn netio_create_client(server_ip: *const c_char, port: c_int) -> *mut c_void;
    fn netio_destroy(handle: *mut c_void);
    
    // AG2PC 函数
    fn emp_ag2pc_create(io: *mut c_void, party: c_int) -> *mut c_void;
    fn emp_ag2pc_destroy(handle: *mut c_void);
    fn emp_ag2pc_garble(handle: *mut c_void, input_a: u64) -> c_int;
    fn emp_ag2pc_eval(handle: *mut c_void, input_b: u64) -> c_int;
    fn emp_ag2pc_get_result(handle: *mut c_void, result: *mut bool) -> c_int;
    fn emp_ag2pc_get_last_error() -> *const c_char;
}

/// 网络连接句柄
pub struct NetIO {
    handle: *mut c_void,
}

impl NetIO {
    /// 创建服务器端网络连接（Alice 使用）
    pub fn create_server(port: u16) -> Result<Self, String> {
        let handle = unsafe { netio_create_server(port as c_int) };
        if handle.is_null() {
            let error = unsafe { get_last_error() };
            return Err(format!("Failed to create server: {}", error));
        }
        Ok(NetIO { handle })
    }
    
    /// 创建客户端网络连接（Bob 使用）
    pub fn create_client(server_ip: &str, port: u16) -> Result<Self, String> {
        let c_ip = CString::new(server_ip)
            .map_err(|e| format!("Invalid server IP: {}", e))?;
        let handle = unsafe { netio_create_client(c_ip.as_ptr(), port as c_int) };
        if handle.is_null() {
            let error = unsafe { get_last_error() };
            return Err(format!("Failed to create client: {}", error));
        }
        Ok(NetIO { handle })
    }
    
    /// 获取底层句柄（用于内部使用）
    pub(crate) fn handle(&self) -> *mut c_void {
        self.handle
    }
}

impl Drop for NetIO {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                netio_destroy(self.handle);
            }
        }
    }
}

/// AG2PC 协议实例
pub struct Ag2pc {
    handle: *mut c_void,
}

impl Ag2pc {
    /// 创建新的 AG2PC 实例
    pub fn new(netio: &NetIO, party: Party) -> Result<Self, String> {
        let party_int = match party {
            Party::Alice => ALICE,
            Party::Bob => BOB,
        };
        let handle = unsafe { emp_ag2pc_create(netio.handle(), party_int) };
        if handle.is_null() {
            let error = unsafe { get_last_error() };
            return Err(format!("Failed to create AG2PC instance: {}", error));
        }
        Ok(Ag2pc { handle })
    }
    
    /// 执行混淆电路协议（Alice/Garbler）
    pub fn garble(&mut self, input_a: u64) -> Result<(), Ag2pcError> {
        let result = unsafe { emp_ag2pc_garble(self.handle, input_a) };
        if result != EMP_AG2PC_SUCCESS {
            let error = unsafe { get_last_error() };
            return Err(Ag2pcError::Protocol(format!("Garble failed: {}", error)));
        }
        Ok(())
    }
    
    /// 执行混淆电路协议（Bob/Evaluator）
    pub fn eval(&mut self, input_b: u64) -> Result<(), Ag2pcError> {
        let result = unsafe { emp_ag2pc_eval(self.handle, input_b) };
        if result != EMP_AG2PC_SUCCESS {
            let error = unsafe { get_last_error() };
            return Err(Ag2pcError::Protocol(format!("Eval failed: {}", error)));
        }
        Ok(())
    }
    
    /// 获取比较结果
    pub fn get_result(&self) -> Result<bool, Ag2pcError> {
        let mut result = false;
        let ret = unsafe { emp_ag2pc_get_result(self.handle, &mut result) };
        if ret != EMP_AG2PC_SUCCESS {
            let error = unsafe { get_last_error() };
            return Err(Ag2pcError::Protocol(format!("Get result failed: {}", error)));
        }
        Ok(result)
    }
}

impl Drop for Ag2pc {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                emp_ag2pc_destroy(self.handle);
            }
        }
    }
}

/// 协议参与方
#[derive(Debug, Clone, Copy)]
pub enum Party {
    Alice,
    Bob,
}

/// AG2PC 错误类型
#[derive(Debug)]
pub enum Ag2pcError {
    Init(String),
    Network(String),
    Protocol(String),
}

impl std::fmt::Display for Ag2pcError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Ag2pcError::Init(msg) => write!(f, "Initialization error: {}", msg),
            Ag2pcError::Network(msg) => write!(f, "Network error: {}", msg),
            Ag2pcError::Protocol(msg) => write!(f, "Protocol error: {}", msg),
        }
    }
}

impl std::error::Error for Ag2pcError {}

/// 获取最后的错误信息
unsafe fn get_last_error() -> String {
    let c_str = emp_ag2pc_get_last_error();
    if c_str.is_null() {
        return "Unknown error".to_string();
    }
    CStr::from_ptr(c_str)
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // 注意：这些测试需要实际的网络连接和 emp-ag2pc 库
    // 在实际环境中运行
    
    #[test]
    #[ignore]
    fn test_network_creation() {
        let netio = NetIO::create_server(12345);
        assert!(netio.is_ok());
    }
}
