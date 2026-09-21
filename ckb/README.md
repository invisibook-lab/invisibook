# CKB 侧

Proof of Buy 在 CKB 上的合约。链上布局与验证规则见
[../docs/ckb_layout.md](../docs/ckb_layout.md)。

```
contracts/
  pob-submission/    提交 cell 的 type script（未实现，一律拒绝）
```

## 链上做什么

出价以承诺形式提交，L1 上没有明文可验：VRF、goal、身份、zk 一律由 L2 节点校验。
链上只剩两个脚本，都很轻：

| 脚本 | 职责 | 规则 | 现状 |
| --- | --- | --- | --- |
| `budget_type_script` | 预算 cell：预付款与支付承诺，写入后不可改 | R3.1~R3.4 | 未实现 |
| `commit_type_script` | 提交 cell：只检查 data 是 32 字节 | R4.1~R4.2 | 未实现 |

规则全文见 ckb_layout.md §3~§4，L2 侧要自己完成的校验清单见 §5。

`contracts/pob-submission` 目前**没有实现任何规则，对所有交易返回失败**。type script
若在规则写完之前返回成功，等于无条件放行任何交易，所以它必须 fail closed。

这里没有任何密码学代码，也不该有。链上不打开承诺、不验 VRF、不验 zk 证明，脚本里多
一个密码学 crate 就多一份被编进去、按字节占 cell capacity 的开销，换不回任何东西。

## 工具链

编译合约需要：

```
rustup target add riscv64imac-unknown-none-elf
brew install riscv64-elf-gcc      # ckb-std 的 build script 需要
cargo install ckb-debugger
```

`ckb-std` 通过 cc-rs 编译一段 C，默认去找 `riscv64-unknown-elf-gcc`，而 brew 装出来
的叫 `riscv64-elf-gcc`。两者只是名字不同，用环境变量指过去即可：

```
export CC_riscv64imac_unknown_none_elf=riscv64-elf-gcc
export AR_riscv64imac_unknown_none_elf=riscv64-elf-ar
```
