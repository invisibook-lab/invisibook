# CKB 侧

Proof of Buy 在 CKB 上的合约与配套工具。链上布局与验证规则见
[../docs/ckb_layout.md](../docs/ckb_layout.md)。

```
vrf/                 ECVRF 验证，no_std，与 L2 侧 prover 字节级一致
bench/               裸机度量程序，测密码学本身的 cycle 开销
bench-std/           同上，但链入 ckb-std，用来看框架自身的开销
contracts/
  pob-submission/    提交 cell 的 type script（未实现，一律拒绝）
```

`contracts/pob-submission` 目前**没有实现任何规则，对所有交易返回失败**。type script
若在规则写完之前返回成功，等于无条件放行任何交易，所以它必须 fail closed。

链上只剩两个脚本，且都很轻——出价以承诺形式提交，L1 没有明文可验，VRF、goal、
身份、zk 一律由 L2 节点校验：

| 脚本 | 职责 | 规则 | 现状 |
| --- | --- | --- | --- |
| `budget_type_script` | 预算 cell：预付款与支付承诺，写入后不可改 | R3.1~R3.4 | 未实现 |
| `commit_type_script` | 提交 cell：只检查 data 是 32 字节 | R4.1~R4.2 | 未实现 |

规则全文见 ckb_layout.md §3~§4，L2 侧要自己完成的校验清单见 §5。

`vrf/`、`bench/`、`bench-std/` 当初是为在链上验 ECVRF 做的，那条路已经不走了。实测
的 cycle 数仍然有效，只是不再构成约束；这份 Rust 实现留着是因为它是 L2 侧 Go prover
的独立交叉验证，两套实现对同一组向量必须得出同一个 `beta`。

## 工具链

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

`vrf` 与 `bench` 不依赖 ckb-std，不需要这两个变量。

## 验证 ECVRF 与 L2 一致

L2 侧的 prover 产出的证明，必须能被链上的 verifier 接受，且推出同一个 `beta`。任何
一处不一致都会让两层对同一个高度选出不同的赢家。

生成向量（L2 侧）：

```
cd ../chain && go test ./consensus/ -run TestPrintVRFVector -v
```

对照验证（CKB 侧）：

```
cargo test --manifest-path vrf/Cargo.toml
```

`vrf` 的测试里固化了一组来自 L2 的向量，并覆盖了改输入、改证明、换公钥三种否定用例。

## 测量 cycle

```
cargo build --manifest-path bench/Cargo.toml \
    --target riscv64imac-unknown-none-elf --release
ckb-debugger --bin bench/target/riscv64imac-unknown-none-elf/release/vrf-bench
```

`bench-std` 同理（需要上面两个环境变量）。当前结果，一次 ECVRF 验证：

| 构建 | cycles | 脚本体积 |
| --- | --- | --- |
| `bench`，裸机，`opt-level = 3` | 7,618,328 | — |
| `bench-std`，链入 ckb-std，`opt-level = 3` | 7,742,724 | 109,208 B |
| `bench-std`，链入 ckb-std，`opt-level = "z"` | 8,817,578 | 89,376 B |

两件事值得分开看：

- **ckb-std 自身很便宜**：同为 `opt-level = 3`，接上入口与分配器只多 124,396 cycles，
  约 1.6%。
- **`opt-level` 的取舍不便宜**：换成 `"z"` 省下 19,832 字节的脚本体积，代价是多
  1,074,854 cycles，约 14%。CKB 上脚本体积直接占用 cell capacity（1 CKB = 1 字节，
  且被锁住），所以这是一笔真实的权衡，等规则写完、体积定型后再决定。

无论哪个档位，相对主网 35 亿的区块 cycle 上限都在 0.25% 以内，单个区块容得下数百次
这样的验证。

两端输入都套了 `black_box`，防止优化器把已知结果折成常量。度量程序用固定向量，是为了
让数字可复现——它们是 benchmark，不是合约。
