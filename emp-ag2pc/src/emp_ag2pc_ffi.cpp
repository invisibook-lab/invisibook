// emp-ag2pc FFI 实现
// 将 C++ API 封装为 C 接口供 Rust 调用

#include "emp_ag2pc_ffi.h"
#include <string>
#include <cstring>
#include <memory>

// 假设 emp-ag2pc 和 emp-tool 的头文件路径
// 实际使用时需要根据安装路径调整
#ifdef __cplusplus
#include "emp-ag2pc/ag2pc.h"
#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/circuit_file.h"
#include "emp-tool/circuits/integer.h"
#include "emp-tool/io/net_io_channel.h"

using namespace emp;

// 错误信息存储
static thread_local std::string last_error;

// 网络连接包装类
class NetIOWrapper {
public:
    NetIO* io;
    
    NetIOWrapper(NetIO* io_ptr) : io(io_ptr) {}
    ~NetIOWrapper() {
        if (io) {
            delete io;
        }
    }
};

// AG2PC 包装类
class AG2PCWrapper {
public:
    AG2PC* ag2pc;
    NetIOWrapper* netio;
    Circuit* circuit;
    bool result_ready;
    bool result_value;
    
    AG2PCWrapper(NetIOWrapper* netio_wrapper, int party) 
        : netio(netio_wrapper), result_ready(false) {
        try {
            ag2pc = new AG2PC(netio_wrapper->io, party);
            circuit = new Circuit();
        } catch (...) {
            ag2pc = nullptr;
            circuit = nullptr;
        }
    }
    
    ~AG2PCWrapper() {
        if (ag2pc) {
            delete ag2pc;
        }
        if (circuit) {
            delete circuit;
        }
    }
};

// 构建 64 位整数比较电路
void build_comparison_circuit(Circuit* circ, Integer& a, Integer& b) {
    // 计算 a > b
    // 使用减法：a - b，然后检查符号位
    Integer diff = a - b;
    
    // 检查符号位（最高位）
    Bit is_negative = diff[63];
    
    // 检查是否为零
    Bit is_zero = true;
    for (int i = 0; i < 64; i++) {
        is_zero = is_zero && !diff[i];
    }
    
    // a > b 等价于 diff > 0，即 !is_negative && !is_zero
    Bit a_greater_than_b = !is_negative && !is_zero;
    
    circ->output(a_greater_than_b);
}

extern "C" {

NetIOHandle netio_create_server(int port) {
    try {
        NetIO* io = new NetIO(nullptr, port);
        return new NetIOWrapper(io);
    } catch (const std::exception& e) {
        last_error = e.what();
        return nullptr;
    } catch (...) {
        last_error = "Unknown error creating server";
        return nullptr;
    }
}

NetIOHandle netio_create_client(const char* server_ip, int port) {
    try {
        NetIO* io = new NetIO(server_ip, port);
        return new NetIOWrapper(io);
    } catch (const std::exception& e) {
        last_error = e.what();
        return nullptr;
    } catch (...) {
        last_error = "Unknown error creating client";
        return nullptr;
    }
}

void netio_destroy(NetIOHandle handle) {
    if (handle) {
        delete static_cast<NetIOWrapper*>(handle);
    }
}

EmpAg2pcHandle emp_ag2pc_create(NetIOHandle io, int party) {
    if (!io) {
        last_error = "Invalid network handle";
        return nullptr;
    }
    
    if (party != ALICE && party != BOB) {
        last_error = "Invalid party, must be ALICE or BOB";
        return nullptr;
    }
    
    try {
        NetIOWrapper* netio_wrapper = static_cast<NetIOWrapper*>(io);
        AG2PCWrapper* wrapper = new AG2PCWrapper(netio_wrapper, party);
        
        if (!wrapper->ag2pc || !wrapper->circuit) {
            delete wrapper;
            last_error = "Failed to create AG2PC instance";
            return nullptr;
        }
        
        return wrapper;
    } catch (const std::exception& e) {
        last_error = e.what();
        return nullptr;
    } catch (...) {
        last_error = "Unknown error creating AG2PC";
        return nullptr;
    }
}

void emp_ag2pc_destroy(EmpAg2pcHandle handle) {
    if (handle) {
        delete static_cast<AG2PCWrapper*>(handle);
    }
}

int emp_ag2pc_garble(EmpAg2pcHandle handle, uint64_t input_a) {
    if (!handle) {
        last_error = "Invalid AG2PC handle";
        return EMP_AG2PC_ERROR_INIT;
    }
    
    try {
        AG2PCWrapper* wrapper = static_cast<AG2PCWrapper*>(handle);
        
        // 创建输入
        Integer a(64, input_a);
        Integer b(64, 0);  // Bob 的输入将在 eval 时设置
        
        // 构建电路
        build_comparison_circuit(wrapper->circuit, a, b);
        
        // 执行混淆协议
        wrapper->ag2pc->garble(wrapper->circuit, &a, nullptr);
        
        // 获取结果
        bool result = wrapper->circuit->get_output_bit(0);
        wrapper->result_value = result;
        wrapper->result_ready = true;
        
        return EMP_AG2PC_SUCCESS;
    } catch (const std::exception& e) {
        last_error = e.what();
        return EMP_AG2PC_ERROR_PROTOCOL;
    } catch (...) {
        last_error = "Unknown error in garble";
        return EMP_AG2PC_ERROR_PROTOCOL;
    }
}

int emp_ag2pc_eval(EmpAg2pcHandle handle, uint64_t input_b) {
    if (!handle) {
        last_error = "Invalid AG2PC handle";
        return EMP_AG2PC_ERROR_INIT;
    }
    
    try {
        AG2PCWrapper* wrapper = static_cast<AG2PCWrapper*>(handle);
        
        // 创建输入
        Integer a(64, 0);  // Alice 的输入已在 garble 时设置
        Integer b(64, input_b);
        
        // 构建电路（需要与 garble 端相同的电路）
        build_comparison_circuit(wrapper->circuit, a, b);
        
        // 执行评估协议
        wrapper->ag2pc->eval(wrapper->circuit, nullptr, &b);
        
        // 获取结果
        bool result = wrapper->circuit->get_output_bit(0);
        wrapper->result_value = result;
        wrapper->result_ready = true;
        
        return EMP_AG2PC_SUCCESS;
    } catch (const std::exception& e) {
        last_error = e.what();
        return EMP_AG2PC_ERROR_PROTOCOL;
    } catch (...) {
        last_error = "Unknown error in eval";
        return EMP_AG2PC_ERROR_PROTOCOL;
    }
}

int emp_ag2pc_get_result(EmpAg2pcHandle handle, bool* result) {
    if (!handle) {
        last_error = "Invalid AG2PC handle";
        return EMP_AG2PC_ERROR_INIT;
    }
    
    if (!result) {
        last_error = "Invalid result pointer";
        return EMP_AG2PC_ERROR_INIT;
    }
    
    AG2PCWrapper* wrapper = static_cast<AG2PCWrapper*>(handle);
    
    if (!wrapper->result_ready) {
        last_error = "Result not ready";
        return EMP_AG2PC_ERROR_PROTOCOL;
    }
    
    *result = wrapper->result_value;
    return EMP_AG2PC_SUCCESS;
}

const char* emp_ag2pc_get_last_error(void) {
    return last_error.c_str();
}

} // extern "C"

#endif // __cplusplus
