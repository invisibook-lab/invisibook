# 结算安全加固计划(rev.4 增量 — 基于本轮 review)

> 定位:在已批准的 rev.3 方案、已完成的 P0–P4(chain/lib)之上的**增量修改**。
> 本轮讨论挖出一个**确认的时序 bug** + 三个设计缺口,本计划逐条给出修法、
> 设计决策、文件触点、工作量。

---

## 一、本轮 review 的发现

| # | 级别 | 发现 | 位置 |
|---|---|---|---|
| F1 | **P0 确认 bug** | **reveal 排在 π_cmp 与任何上链动作之前**。恶意大单方可"跑 compare → 收 reveal 学到小单 q → abort",链上零痕迹、无法归责。 | `session.rs:441`(compare)/`444-479`(reveal)/`630`(π_cmp);SubmitCompare 更在其后 |
| F2 | P1 缺口 | **结算非原子**:`settle_small` / `settle_large` 是两笔独立写入,一条腿可先落账、另一条不落(fair-exchange 缺口)。 | `orderbook_cozk.go:455 / 532` |
| F3 | P1 不对称 | **settle_small 不自证"我更小"**(只 settle_large 用 `q_res=q−q_ctr` 的 64-bit range 自证"我更大")。当前靠链上 cmp gate 兜,不是密码学对称。 | `settle_small.circom` vs `settle_large.circom` |
| F4 | P2 缺口 | **abort 无归责**(VI-D):compare 阶段有人 abort,链上无痕、罚不了。 | 全局 |

---

## 二、设计决策(先定方向,再列步骤)

1. **保留链上 compare(方向 B),不砍(不走方向 A)。**
   讨论已表明:砍掉链上 compare、纯双边 + 让两个 settle proof 自证,虽然"正确性"
   够,但会让 compare 阶段的 abort **完全没有链上锚点**,归责更差。而 F1 的修法
   恰恰**依赖**链上 compare 存在且**先于 reveal 落账**。所以保留并强化它。

2. **reveal 严格挪到"链上 SubmitCompare 落账之后"。** 这是 F1 的修法核心,把
   "无痕不可归责"降级为"Settling 但未 settle → 可归责"。

3. **用一笔原子 `SettlePair` 恢复结算原子性(F2)。** 最简单的"要么都成、要么
   都不成",不引入押金/罚没。

4. **VI-D 的押金/超时/罚没(F4)先设计、暂不实现。** 真 fairness 不可能(Cleve),
   链只能给 fairness-with-penalties;这块重,排在 A、B 之后。

---

## 三、Phase A(P0,必修)— 重排:链上 compare 先于 reveal

**把 `run_session` 拆成两段,中间夹一次上链。**

### A.1 Compare 会话(MPC,产出可上链的 π_cmp)
`run_compare_session`:preamble → share+bind 检查 → `compare_three_way` → 交换双签
→ 协作证 π_cmp → 返回 `{cmp, public, proof_hex, sig_a, sig_b}`。
**不做 reveal、不派生收款 note。**

### A.2 上链 SubmitCompare(已存在的 writing)
host 提交 `SubmitCompareCoZk`(π_cmp + 双签)→ 链验证 → 记录 cmp、两单转 Settling。
**host 等确认**(两单 = Settling)后才进入 A.3。

### A.3 Settle 阶段(此后才 reveal,且**不再需要 SPDZ**)
- 小单方把 `(q, r)` 发给大单方(明文,走 P2P);
- 大单方**直接本地校验** `Poseidon(q, r) == cm_q_ctr`(对方的**链上**承诺)——
  链上承诺就是校验源,不再需要 fabric 里的 `open_expect_zero`;
- 双方交换收款 note 的 `(npk, r)`,WAL 落盘(persist-before-publish);
- 各自跑**单方** settle 电路、提交(见 Phase B 的原子版)。

### A.4 安全效果
- **compare 阶段 abort** → 链上没有 SubmitCompare,两单仍 Matched(未泄露、未锁定);
- **reveal 后 abort** → 链上留"Settling 但未 settle"痕迹 → **可归责**(接 Phase C);
- reveal **永不先于**一个链上锚点发生。F1 关闭。

### A.5 附带收益
Settle 阶段从"MPC 里做 reveal"降为"明文消息 + 本地 Poseidon 校验",**去掉了一段
SPDZ 交互**,更简单。

### A.6 文件触点
- `cozk2p/src/session.rs`:拆 `run_session` → `run_compare_session` + `run_settle_phase`(后者无 fabric)。
- `lib/chain/src/chain.rs`:客户端编排改两段(submit_compare → 等 Settling → reveal → settle)。
- `app/ui/src/settle.rs`、`app/desktop/src/main.rs`:编排改两段(与尚未完成的 app settle 迁移合并做)。
- 链侧无需改(SubmitCompare/Settle* 已在)。

---

## 四、Phase B(P1,强烈建议)— 原子结算 SettlePair

### B.1 新 writing `SettlePair`
一笔写入同时:
- 按记录的 cmp + 两单的链上承诺,验证 **π_A(settle_small)** 与 **π_B(settle_large)** 两个证明;
- 在**一个 GORM 事务**里应用两边变更:铸两张收款 note、关闭小单、按残量 relist 大单。

双方在 A.3 里交换各自的单方证明,任一方提交这一笔。

### B.2 效果
- **两条腿同落或同不落** → 恢复 fair-exchange 原子性(F2 关闭);
- 一方扣着自己证明 = 对称 griefing(两单都留 Settling),**没有"收了款不付款"**;
- 保留两笔独立 `SettleSmall/SettleLarge` 吗?**建议以 SettlePair 为主路径**,独立写入
  仅在需要"部分进展"时保留;为简化,倾向删掉。

### B.3 可选:对称化 settle_small(defense-in-depth,关 F3)
让 `settle_small` 也打开对方承诺 `cm_q_ctr` 并证 `q_mine ≤ q_ctr`(与 settle_large
镜像)。这样即使不信 cmp gate,两个证明**自身**就自证了大小与拆分。成本低(一个
承诺打开 + 一个 range),可与 SettlePair 一起做。

### B.4 文件触点
- `chain/core/`:新增 `SettlePair` writing + 请求结构 + bind;`order_scheme` 状态流转。
- `lib/zk/templates/settle_small.circom`(若做 B.3):加 `cm_q_ctr` 公开输入 + `q ≤ q_ctr`。
- `lib/chain/src/chain.rs`:`submit_settle_pair`;A.3 里加"交换对方证明"。
- `cozk2p/src/relation.rs` **不动**(compare 关系不变)。

---

## 五、Phase C(P2,延后 — 仅设计,暂不实现)— VI-D 归责与罚没

把"可归责"升级为"有代价"。真 fairness 不可能(Cleve),目标是 fairness-with-penalties。

### C.1 轻量档(推荐先做这档)
- **押金**:两单进 Settling 时(或下单时)各押一笔 settlement bond;
- **超时罚没**:SubmitCompare 后 N 个区块内未出现 SettlePair → 一笔 challenge 写入,
  罚没未配合方的 bond、补偿对手方;
- 归责判据:链上"Settling 但未 settle"+ 超时,直接点名。

### C.2 重量档(可选,更强归责)——"把最后 open 上链"
- 协作证产出**分享形式**的 `⟦π_cmp⟧`,两方各自把认证份额贴上链;
- 链**重构 + SNARK 验证**(SNARK 验证顶替 MAC 校验,α 永不上链);
- 门控在"两份齐全"→ fair release + 谁没贴谁被点名;
- 代价:更多链上数据 + 一轮以上;仍受 Cleve 限制(给 penalties,不给真 fairness)。

### C.3 文件触点(预估)
- `chain/core/`:bond 表、challenge/timeout 写入、罚没状态机;
- (重量档)协作证输出分享、链上重构+验证 writing;
- `cozk2p/src/prove.rs`:输出 `⟦π⟧` 分享(仅重量档)。

---

## 六、顺序、工作量、与已完成工作的关系

| Phase | 内容 | 工作量 | 必要性 |
|---|---|---|---|
| **A** | 会话拆两段 + reveal 后置 + settle 阶段去 MPC | 中 | **必修**(关 F1) |
| **B** | SettlePair 原子结算(+ 可选对称化 settle_small) | 中 | 强烈建议(关 F2/F3) |
| **C** | VI-D 押金/超时/罚没(+ 可选链上 open) | 大 | 延后(关 F4) |

- **与尚未完成的 app 迁移合并**:Phase A 本来就要重写 `app/ui/src/settle.rs` 的编排
  (两段化),正好把之前挂起的"settle.rs 读 order 抵押 / trade_form note 下单"一起做掉。
- **链/lib 主体已迁完**(P0–P4),本计划不回退已完成部分;A 主要动 session + app,
  B 动 chain + 可选电路,C 延后。
- **cozk2p 的 compare 关系全程不动**(仍是 3 公开输入的 π_cmp),RELATION_VERSION 不变。

---

## 六点五、实施状态(2026-08-16,第二轮更新)

| 项 | 状态 | commit |
|---|---|---|
| **Phase A** cozk2p 重排:π_cmp + `confirm_compare_onchain` 钩子先于 reveal | ✅ 已实现 + `session_2p` 测试通过 | `025bc61` |
| **Phase B** 链上原子 `SettlePair`(共享 verifySmallLeg/verifyLargeLeg) | ✅ 已实现 + `TestSettlePairAtomic` + 回归测试通过 | `1492a65` |
| **Phase B** lib/chain `settle_pair` 客户端 + 序列化 lockstep 测试 | ✅ 已实现 + 测试通过 | `f27eb08` |
| **Phase 5** cozk2p 会话转 note 模型 + 结算 leg 在纤程内交换 + 分相计时 | ✅ 已实现 + 测试通过 | `d6e81e9` |
| **Phase 5** lib:OrderStore(订单 opening 台账)+ 2-slot 选币 + 池树同步 | ✅ 已实现 + 测试通过 | `0f1398d` |
| **Phase A/5** app 两段编排(`compare_ready` → 上链确认 → reveal → leg → `SettlePair`)+ note 下单 | ✅ 已实现,app 全量编译 | `eb24fc5` |
| **Phase 5c** 全仓删除 cash 模型 + grep-gate 回归闸 | ✅ 已实现 + gate 测试通过 | `f7afde1` |
| Phase B 对称化 settle_small / Phase C VI-D | ⏸ 延后(仅设计) | — |

**F1 abort 语义已有测试钉住:** `compare_abort_precedes_any_reveal`(cozk2p)
证明 compare 无法上链时会话在 reveal 之前中止、无 WAL 落盘;`SettlePair` 的
坏 leg 原子回滚由 Go 侧 `TestSettlePairAtomic` 覆盖。

已落地的 **F1(隐私泄露时序 bug)** 和 **F2(结算原子性)** 在
chain/lib/cozk2p/app 四层全部闭环。

## 七、一句话总结

F1 是必须马上修的真 bug(Phase A:reveal 挪到 SubmitCompare 之后,顺带把 settle 阶段
去掉 MPC);F2/F3 用一笔原子 `SettlePair`(+ 可选对称化 settle_small)干净关闭
(Phase B);F4 的押金/超时/罚没属于 VI-D,先设计、排在最后(Phase C)。方向上**保留
并强化链上 compare**,不走"砍 compare"那条(它会让归责更差)。
