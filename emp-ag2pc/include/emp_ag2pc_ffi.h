// emp-ag2pc FFI 接口头文件
// 用于 Rust 调用 C++ 代码

#ifndef EMP_AG2PC_FFI_H
#define EMP_AG2PC_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

// 角色定义
#define ALICE 1
#define BOB 2

// 错误码
#define EMP_AG2PC_SUCCESS 0
#define EMP_AG2PC_ERROR_INIT -1
#define EMP_AG2PC_ERROR_NETWORK -2
#define EMP_AG2PC_ERROR_PROTOCOL -3

// AG2PC 句柄（不透明指针）
typedef void* EmpAg2pcHandle;

// 网络连接句柄
typedef void* NetIOHandle;

/**
 * 创建网络连接（作为服务器/Alice）
 * @param port 端口号
 * @return 网络连接句柄，失败返回 NULL
 */
NetIOHandle netio_create_server(int port);

/**
 * 创建网络连接（作为客户端/Bob）
 * @param server_ip 服务器IP地址
 * @param port 端口号
 * @return 网络连接句柄，失败返回 NULL
 */
NetIOHandle netio_create_client(const char* server_ip, int port);

/**
 * 销毁网络连接
 * @param handle 网络连接句柄
 */
void netio_destroy(NetIOHandle handle);

/**
 * 创建 AG2PC 实例
 * @param io 网络连接句柄
 * @param party 角色：ALICE 或 BOB
 * @return AG2PC 句柄，失败返回 NULL
 */
EmpAg2pcHandle emp_ag2pc_create(NetIOHandle io, int party);

/**
 * 销毁 AG2PC 实例
 * @param handle AG2PC 句柄
 */
void emp_ag2pc_destroy(EmpAg2pcHandle handle);

/**
 * 执行混淆电路协议（Garbler/Alice）
 * @param handle AG2PC 句柄
 * @param input_a Alice 的输入（64位无符号整数）
 * @return 错误码，0表示成功
 */
int emp_ag2pc_garble(EmpAg2pcHandle handle, uint64_t input_a);

/**
 * 执行混淆电路协议（Evaluator/Bob）
 * @param handle AG2PC 句柄
 * @param input_b Bob 的输入（64位无符号整数）
 * @return 错误码，0表示成功
 */
int emp_ag2pc_eval(EmpAg2pcHandle handle, uint64_t input_b);

/**
 * 获取比较结果
 * @param handle AG2PC 句柄
 * @param result 输出结果指针（true表示 input_a > input_b）
 * @return 错误码，0表示成功
 */
int emp_ag2pc_get_result(EmpAg2pcHandle handle, bool* result);

/**
 * 获取最后错误信息
 * @return 错误信息字符串
 */
const char* emp_ag2pc_get_last_error(void);

#ifdef __cplusplus
}
#endif

#endif // EMP_AG2PC_FFI_H
