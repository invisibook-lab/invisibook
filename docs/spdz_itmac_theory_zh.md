# SPDZ 在线阶段可验证打开(Authenticated Opening)——完整理论

> **Status:** Current(中文理论笔记,背景阅读;与实现的对应关系见
> [cozk2p_design.md](cozk2p_design.md))。

> 说明:本文解释 `cozk2p` 比较协议里"每次打开都是 `open_authenticated`,
> 篡改份额会在 MAC 校验处 abort"这一机制的全部理论细节。
>
> 公式用 `$...$` / `$$...$$`,在 GitHub、Typora、或装了数学插件的 VSCode
> Markdown 预览里可正常渲染。

---

## 0. 场景、域,以及一句诚实的前提

- 两方 MPC(方 P1、P2),记恶意方为 A。
- 域固定为 $\mathbb{F}=\mathbb{F}_r$,即 BN254 的标量域($r\approx 2^{254}$)。
  这也是协作 PLONK 证明的原生域,所以 MPC 与证明同域。

**一个必须先讲清的实现前提:** 下面的定理针对 **在线阶段**
(`open_authenticated`,ark-mpc 的真实 SPDZ 实现)。但 **offline 阶段**
(Beaver 三元组 + 全局 MAC 密钥)在本仓库用的是 `PartyIDBeaverSource`
**mock**(见 `cozk2p/src/lib.rs:17-18`),等于一个可信 dealer 直接发正确的
三元组和 MAC 密钥。所以:在线论证严格成立;端到端 malicious 安全还差一个
真实 offline(MASCOT / LowGear / SoftSpokenOT)。详见第 9 节。

---

## 1. 认证秘密分享 $\llbracket x \rrbracket$ 的定义

存在一个 **全局 MAC 密钥** $\alpha \in \mathbb{F}$,它本身被加法分享:

$$\alpha = \alpha_1 + \alpha_2, \qquad \text{方 } i \text{ 只持有 } \alpha_i.$$

**没有任何一方知道 $\alpha$。**

一个值 $x$ 被"认证分享",记 $\llbracket x \rrbracket$,意思是:

$$x = x_1 + x_2, \qquad \underbrace{m(x)}_{=\ \alpha x} = m_1 + m_2.$$

方 $i$ 持有三元组 $(x_i,\ m_i,\ \alpha_i)$,满足

$$\sum_i x_i = x, \qquad \sum_i m_i = \alpha \cdot x.$$

直观:**MAC 就是"用未知密钥 $\alpha$ 给 $x$ 打的线性标签 $\alpha x$",而这个
标签也被分享。** 谁都看不到 $x$,看不到 $\alpha x$,更看不到 $\alpha$。

---

## 2. 线性运算是"免费"的(本地、无通信、MAC 自动保持)

因为 MAC 是 $\alpha$ 的线性函数、分享是加法的:

| 运算 | 各方本地做什么 | 结果 |
|---|---|---|
| **加法** $\llbracket x\rrbracket+\llbracket y\rrbracket$ | $(x_i+y_i,\ m_i+m_i')$ | 值 $x+y$;MAC $\alpha x+\alpha y=\alpha(x+y)$ ✓ |
| **公开标量乘** $c\cdot\llbracket x\rrbracket$ | $(c\,x_i,\ c\,m_i)$ | 值 $cx$;MAC $\alpha cx$ ✓ |
| **加公开常数** $\llbracket x\rrbracket + a$ | 只有 P1 把 $a$ 加进 $x_1$;**每方**给 MAC 加 $\alpha_i a$ | 值 $x+a$;MAC $\alpha x + \alpha a = \alpha(x+a)$ ✓ |

> 加公开常数时,MAC 修正 $+\alpha_i a$ 用到了 $\alpha_i$——这是 $\alpha$ 被分享
> 而非公开的原因之一。

**关键推论:任何线性组合都不需通信,且 MAC 自动跟随。** Poseidon 的 MDS
线性层、轮常数加法,全是免费的。

---

## 3. 乘法:Beaver 三元组 + 部分打开

域上乘法不能免费。用预处理好的 **认证三元组**
$\llbracket a\rrbracket, \llbracket b\rrbracket, \llbracket c\rrbracket$,
其中 $a, b$ 随机、$c = ab$。计算 $\llbracket x\rrbracket \cdot \llbracket y\rrbracket$:

1. **部分打开** $d = x - a$、$e = y - b$(各方广播这两个的份额);
2. 因为 $a, b$ 均匀随机且不在别处打开,$d, e$ **均匀随机**,不泄露 $x, y$;
3. 本地算(全线性,MAC 自动保持):

$$\llbracket xy \rrbracket \;=\; de \;+\; d\,\llbracket b\rrbracket \;+\; e\,\llbracket a\rrbracket \;+\; \llbracket c\rrbracket.$$

**验证:** $(d+a)(e+b) = de + db + ea + ab = de + d b + e a + c = xy$ ✓

注意第 1 步的部分打开此刻 **未认证**,其 MAC 校验 **推迟** 到最后统一做
(第 4 节)。Poseidon 的 S-box $x^5$ 每个要几次这种乘法;`compare_three_way`
约 65 次 Beaver 乘(`mpc_compare.rs:13`)。

---

## 4. `open_authenticated`:MAC 校验协议(核心)

**普通打开** $x = x_1 + x_2$ 是 **不可信** 的:恶意方可发
$x_2' = x_2 + \delta$,让大家重构出错值 $x' = x + \delta$。
`open_authenticated` 在打开后加一道 **MAC 校验** 抓这种篡改。

### 协议步骤(批量随机线性组合版——实际用的高效版)

设整轮计算里一共做了 $t$ 次 **部分打开**,得到值 $y^{(1)}, \dots, y^{(t)}$
(含所有 Beaver 乘法里的 $d, e$,以及最终要打开的结果)。每个 $y^{(j)}$ 此刻
都还 **未认证**。下面这一次 MAC 校验把它们 **全部一次性** 认证。

**Step 1 — 部分打开(计算过程中已发生)。**
对每个 $j$,各方广播自己对 $y^{(j)}$ 的加法份额并求和,得到公开值 $y^{(j)}$。
恶意方可能在这里发过错份额,使某个 $y^{(j)}$ 偏离真值 $x^{(j)}$——这正是要抓的对象。

**Step 2 — 采样公开随机系数。**
在 **所有** $y^{(j)}$ 都固定之后,双方用掷币 / 随机预言(对已包含这些 $y^{(j)}$
的公开抄本)共同采样 $\chi_1, \dots, \chi_t \in \mathbb{F}$。
> 必须"固定之后"再采样:否则恶意方能针对已知的 $\chi$ 定制自己的误差,使其
> 恰好抵消。

**Step 3 — 本地聚合(无通信)。**
每方 $i \in \{1, 2\}$ 本地算三个量:

$$
y = \sum_j \chi_j\, y^{(j)} \quad (\text{公开,人人可算}), \qquad
\mu_i = \sum_j \chi_j\, m_i^{(j)} \quad (\text{自己的 MAC 聚合份额}),
$$

$$
\boxed{\ \sigma_i = \mu_i - \alpha_i \cdot y\ } \quad (\text{自己的校验份额}).
$$

**Step 4 — 承诺(commit)。**
每方取新鲜随机数 $\rho_i$,广播哈希承诺 $\mathrm{Com}_i = H(\sigma_i \,\|\, \rho_i)$。
> 承诺必须在打开 $\sigma_i$ **之前** 完成(理由见本节末)。

**Step 5 — 打开并互验承诺。**
收齐两个承诺后,每方广播 $(\sigma_i, \rho_i)$;双方各自核对对方的
$\mathrm{Com}_i$ 是否与 $(\sigma_i, \rho_i)$ 一致,不一致 → **abort**。

**Step 6 — 判定。**
计算 $\sigma_1 + \sigma_2$:
- $= 0$ → 接受本轮所有打开值 $y^{(j)}$(以及依赖它们的输出);
- $\neq 0$ → **abort**(有人篡改了份额)。

> `open_authenticated` 就是把 Step 1–6 封装起来:成功返回打开值;MAC 校验失败
> 返回 `Err`,我们的代码把 `Err` 映射成 abort。

### 为什么 Step 6 的判据是 $\sigma_1 + \sigma_2 = 0$

把两方 Step 3 的份额相加:

$$\sigma_1 + \sigma_2
= \sum_j \chi_j \underbrace{(m_1^{(j)} + m_2^{(j)})}_{\text{诚实 MAC} =\ \alpha x^{(j)}}
- \underbrace{(\alpha_1 + \alpha_2)}_{=\ \alpha} \underbrace{\sum_j \chi_j\, y^{(j)}}_{=\ y}
= \alpha \sum_j \chi_j \big( x^{(j)} - y^{(j)} \big).$$

这里 $x^{(j)}$ 是 **真值**(MAC 认证的对象),$y^{(j)}$ 是 **实际打开值**。
若无人篡改($y^{(j)} = x^{(j)}$ 对所有 $j$),整式 $= 0$;否则它等于 $\alpha$
乘上一个非零误差组合——恶意方为何补不平这个差,见第 5 节。

### 为什么 Step 4 的"先 commit 再 open"必不可少

若跳过承诺、Step 5 直接广播 $\sigma_i$:恶意方(rushing)可以 **先看** 诚实方的
$\sigma_1$,再令自己的 $\sigma_2^{*} = -\sigma_1$,于是 $\sigma_1 + \sigma_2^{*} = 0$
恒成立,校验形同虚设。承诺把 $\sigma_2^{*}$ 在看到 $\sigma_1$ **之前** 钉死,
堵死这条路。

---

## 5. 可靠性定理 + 伪造概率(为什么"翻不过来")

> **定理(单值版,伪造概率 $1/|\mathbb{F}|$)。**
> 设恶意方把某个值打开成 $x' = x + \delta$,$\delta \neq 0$。
> 则 MAC 校验通过的概率恰为 $\dfrac{1}{|\mathbb{F}|}$。

**证明。** 两方,诚实方 P1、恶意方 A(知道 $\alpha_2$,不知道 $\alpha_1$;而
$\alpha_1$ 在 $\mathbb{F}$ 上均匀且从不泄露)。单值取 $\chi = 1$。诚实方份额:

$$\sigma_1 = m_1 - \alpha_1 x'.$$

代入 $m_1 = \alpha_1 x + c$,其中 $c = \alpha_2 x - m_2$ 是 A 完全已知的量:

$$\sigma_1 = \alpha_1 x + c - \alpha_1 x'
= -\alpha_1 \underbrace{(x' - x)}_{=\ \delta} + c
= -\alpha_1 \delta + c.$$

校验通过 $\iff \sigma_2^{*} = -\sigma_1 = \alpha_1 \delta - c$。A 必须在承诺阶段
**提前钉死** $\sigma_2^{*}$;等式成立 $\iff \sigma_2^{*} + c = \alpha_1 \delta$。

- 左边 $\sigma_2^{*} + c$:A 已知并已固定。
- 右边 $\alpha_1 \delta$:因 $\delta \neq 0$ 且域是整环,$t \mapsto t\delta$ 是双射;
  $\alpha_1$ 均匀 $\Rightarrow$ $\alpha_1 \delta$ 在 A 视角里 **均匀且未知**。

故 A 猜中概率 $= \dfrac{1}{|\mathbb{F}|}$。$\qquad\blacksquare$

### 批量版:$\le 2/|\mathbb{F}|$

令 $\Delta = \sum_j \chi_j \delta_j$。两种漏网可能:

1. **MAC 伪造**:同上,需猜中 $\alpha_1 \Delta$,概率 $\dfrac{1}{|\mathbb{F}|}$;
2. **误差被随机系数消掉**:即使某些 $\delta_j \neq 0$,恰好 $\Delta = 0$。
   但 $\Delta$ 是关于随机 $\chi$ 的 **非零一次多项式**,由 Schwartz–Zippel,
   $\Pr_\chi[\Delta = 0] \le \dfrac{1}{|\mathbb{F}|}$。

并集界 $\Rightarrow$ 总伪造概率

$$\Pr[\text{接受错误打开}] \;\le\; \frac{2}{|\mathbb{F}|} \;\approx\; \frac{2}{2^{254}} \;=\; 2^{-253}.$$

**这就是"没人能靠捣乱份额把比较结果翻过来"的严格含义:** 任何一处发错份额、
算错本地乘法、篡改中间打开,都会在最终那道 `open_authenticated` 上留下非零
$\delta$;蒙混过关 $\equiv$ 在信息论隐藏的 $\alpha$ 下伪造 $\alpha\delta$,
概率 $2^{-253}$。

---

## 6. $\alpha$ 的隐藏 + 部分打开为何不泄露隐私

- **$\alpha$ 的信息论隐藏是安全基石。** 第 5 节证明只用到"$\alpha_1$ 对 A
  均匀未知",这是 information-theoretic 的(不依赖任何计算假设)——所以叫
  IT-MAC。$\alpha$ 全程不打开(打开它 = 交出伪造能力)。
- **中间打开为何不漏。** 每个 $d = x - a$ 被独立均匀的 $a$ 一次一密掩盖
  $\Rightarrow$ 均匀 $\Rightarrow$ 零泄露。最终只打开 **预期输出**:比较里的
  $cmp$、bind 检查里的 $0$。除输出外无泄露——这也是"隐私攻击够不着"的底层原因。

---

## 7. 落到 `cozk2p` 的代码

| 代码 | SPDZ 语义 |
|---|---|
| `fabric.share_scalar(v, owner)` (`session.rs:428-431`) | **输入协议**:用预处理的认证随机掩码 $\llbracket r\rrbracket$ 打开给 owner,owner 广播 $v - r$,于是 $\llbracket v\rrbracket = \llbracket r\rrbracket + (v-r)$ 成为 **带 MAC** 的分享。owner 无法输入一个"无 MAC"的值。 |
| `poseidon_hash(fabric, v, r)` | 把 Poseidon 置换当算术电路在 MPC 里跑(线性层免费,S-box 走 Beaver 乘),输出认证的 $\llbracket \mathrm{Poseidon}(v,r)\rrbracket$。 |
| `bind = ⟦Poseidon⟧ − order_pub` | 减公开常数,仍认证。 |
| `open_expect_zero(bind)` (`session.rs:363-371`) | `open_authenticated` 做"部分打开 + 第 4 节 MAC 校验",再断言值 $= 0$。想让非零 bind 打开成 $0$ = 第 5 节伪造 = $2^{-253}$。 |
| `compare_three_way` (`mpc_compare.rs:133-139`) | $\ge$ 用"掩码打开 + 取 $d = c - r$ 的第 64 位"实现(素域无序,不能直接看符号,必须位分解;每位一次 Beaver 乘),最终 `open_authenticated` 认证地打开 $\ge(a,b)$ 与 $\ge(b,a)$。任何环节篡改都在这两次认证打开处 abort。 |

---

## 8. IT-MAC 保证什么、**不**保证什么(边界)

1. **保证:相对"已分享输入"的计算完整性,或 abort。**
   打开的结果要么是"你们喂进 $\llbracket\cdot\rrbracket$ 的输入的正确函数值",
   要么 abort。它 **不保证** 输入等于任何链外对象。
   → 所以我们在 MPC 里额外加 **bind 检查**(第 7 节),把"相对你输入正确"
   升级为"相对你 **链上承诺的订单** 正确"。这是两层防线的第二层。

2. **不保证三元组本身正确($c = ab$)。**
   在线 MAC 只保证线性关系与打开值的完整性;三元组 $c = ab$ 的正确性是
   **offline 阶段** 的责任(真实 SPDZ 用 sacrifice / MASCOT 组合检查保证)。

3. **不保证 fairness。**
   SPDZ 是 **security-with-abort**:恶意方总能在自己份额/签名公开前 abort。
   IT-MAC 只保证"错的结果过不了",**保证不了"对方一定把协议跑完"**——这正好
   接上 abort 归责问题(我们的 VI-D 缺口)。

---

## 9. 诚实警告:我们的 offline 是 mock 的

- 上面第 5 节定理针对 **在线阶段**;ark-mpc 的 `open_authenticated` 是它的
  真实实现,可靠性论证 **都成立**。
- 但三元组和 $\alpha$ 来自 `PartyIDBeaverSource` **mock**(`cozk2p/src/lib.rs:17-18`),
  等于一个可信 dealer 直接发正确三元组和 MAC 密钥。
- 后果:第 5 节的 $2^{-253}$ 伪造界,在 **假设三元组与 $\alpha$ 由诚实 offline
  产生** 的前提下严格成立;把 mock 换成真实 offline(MASCOT / LowGear /
  SoftSpokenOT——在无可信 dealer 下生成 **带 MAC、经 sacrifice 验证的** 三元组),
  是从"demo 正确"到"生产 malicious-secure"要补的那一步。与"生产要换真实 SRS
  ceremony"同级别。

---

## 参考

- Damgård, Pastro, Smart, Zakarias. *Multiparty Computation from Somewhat
  Homomorphic Encryption* (SPDZ). CRYPTO 2012.
- Keller, Orsini, Scholl. *MASCOT: Faster Malicious Arithmetic Secure
  Computation with Oblivious Transfer*. CCS 2016.
- Damgård, Keller, Larraia, Pastro, Scholl, Smart. *Practical Covertly Secure
  MPC for Dishonest Majority* (SPDZ-2). ESORICS 2013.(MAC 校验 + sacrifice 细节)
- Catrina, de Hoogh. *Improved Primitives for Secure Multiparty Integer
  Computation*. SCN 2010.(素域上的比较/位分解)
