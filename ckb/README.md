# CKB 侧

Proof of Buy 在 CKB 上的合约。链上布局与验证规则见
[../docs/ckb_layout.md](../docs/ckb_layout.md)。

```
contracts/
  pob-budget/        预算 cell 的 type script（R3.1、R3.3~R3.5，已实现；R3.2 待 zk）
  pob-submission/    提交 cell 的 type script（R5.1，已实现）
  pob-vault/         mining addr 的 type script（R4.0，已实现）
  pob-spent/         已用代币的标记 type script（R4.1~R4.2，已实现）
tests/               合约的规则测试，独立 crate
```

合约与测试分成两个 crate 是必须的，不是风格选择：合约是 no_std、no_main 的 RISC-V
二进制，在宿主机上根本链接不起来，而测试需要 std 并跑在宿主机上。测试从磁盘读取编译
好的脚本、放进一笔构造出来的交易里执行，因此从不链接合约 crate。

## 链上做什么

出价以承诺形式提交，L1 上没有明文可验：VRF、goal、身份、zk 一律由 L2 节点校验。
链上只剩两个脚本，都很轻：

| 脚本 | 职责 | 规则 | 现状 |
| --- | --- | --- | --- |
| `budget_type_script` | 预算 cell：一次写定的分配表，含预付总额 | R3.1、R3.3~R3.5 | **已实现**（`contracts/pob-budget`） |
| `mining_addr_type_script` | mining addr：钱流出时强制打标记 | R4.0 | **已实现**（`contracts/pob-vault`） |
| `spent_type_script` | 已用代币 cell：标记只增不减，且回不去 mining addr | R4.1~R4.2 | **已实现**（`contracts/pob-spent`） |
| `commit_type_script` | 提交 cell：只检查 data 是 32 字节 | R5.1~R5.2 | **已实现**（`contracts/pob-submission`） |

规则全文见 ckb_layout.md §3~§4，L2 侧要自己完成的校验清单见 §5。

`contracts/pob-submission` 实现的就是 R5.1：遍历本脚本守护的 outputs，每个 cell 的
data 必须恰好 32 字节。inputs 一律不管——提交 cell 由矿工用自己的 lock 花掉以回收
容量，那是 lock 的事（R5.2）。

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

## 编译与测试

```
for c in pob-budget pob-submission pob-vault pob-spent; do
    cargo build --manifest-path contracts/$c/Cargo.toml \
        --target riscv64imac-unknown-none-elf --release
done

cargo test --manifest-path tests/Cargo.toml
```

`--nocapture` 可以顺带读出每个脚本的实测 cycle 数——`verify_tx` 本来就返回它，不需要
单独的度量程序。

## 部署

四个脚本逐链部署，没有固定地址，devnet 每次重置都要重来一遍。`chain/cmd/ckb-deploy`
把编译好的四个二进制发成一笔交易里的四个 code cell，并把 L2 节点要的整段 `[ckb]`
配置打到 stdout：

```
cd chain && go run ./cmd/ckb-deploy \
    -rpc http://127.0.0.1:8114 -network devnet \
    -sighash-dep 0x<devnet 创世交易> \
    -mining-addr ckt1... \
    -key-file ./devnet-miner.key >> cfg/core.toml
```

四个一笔发完，是因为它们本就是一套——彼此用对方的哈希做参数，只有一半的链没有意义。
`hash_type` 取 `data1`，code hash 就是二进制本身的哈希，节点跑的脚本由配置唯一确定，
不存在被换掉的可能。

## 一条会咬人的限制

CKB-VM **不执行 RISC-V 的原子指令**（`lr.d` / `sc.d`）。目标三元组 `riscv64im**a**c`
里的 `a` 允许编译器生成它们，于是任何引入原子引用计数的代码都会让脚本在运行期炸成
`VM Internal Error: InvalidInstruction`。

最容易踩到的是 `high_level::load_script()`：它返回的 molecule `Script`，其 `args()`
产出一个持有引用计数的 `Bytes`，克隆即触发原子操作。`pob-spent` 因此改走
`syscalls::load_script` 把数据读进栈上缓冲区，再用借用式的 `ScriptReader` 解析。

判断有没有踩雷，反汇编一扫即知：

```
riscv64-elf-objdump -d <脚本> | grep -cE "\b(lr\.[wd]|sc\.[wd]|amo)"
```

结果必须是 0。

测试必须在编译之后跑——它读的就是上一条命令产出的那个二进制。

注意 `ckb-debugger --bin <脚本>` 只能说明二进制装载得起来：没有交易上下文时
`GroupOutput` 是空的，规则那段循环一次都不会进，于是无论规则写成什么都返回成功。要
验证规则，只能像 `tests/` 里那样构造真实交易。

## 端到端联调

`scripts/devnet.sh up` 把整条路径在本地跑通:起一个 CKB devnet(创世里给矿工发好
资金、打开 Indexer RPC)、编译并部署四个脚本、建预算 cell、等够 V4 的 24 个 L1 区块、
起 L2 节点、申报开启值。`status` 看进度,`logs` 跟日志,`clean` 全部清掉。

等 24 个区块不是保守起见:V4 比的是预算交易与**区块自己的锚定**之间的 L1 高度差,而
锚定高度一经确定就不再变——L2 起得太早,最初那批区块会永远落不了盘。
