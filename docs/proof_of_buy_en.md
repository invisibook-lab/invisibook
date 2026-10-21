# Proof of Buy

A Layer 2 consensus protocol designed around a Layer 1.

> [中文版](proof_of_buy.md)

## 1. Overview

Proof of Buy (PoB) buys the right to produce L2 blocks with **money actually spent
on L1**, in place of **coins locked up on L2**. A VRF weights each payment randomly
to decide the winner at every height; the block header is then anchored back to L1,
where L1 keeps a backup of that history and confers finality on it.

PoB belongs to the PoW family: producing a block carries an irrevocable real cost,
the result is objectively verifiable, and no subjective voting enters anywhere. It
differs from merged mining in what it reuses — the **past hashpower** already
crystallised into L1 tokens, not L1's live hashpower. L1 miners' hashpower therefore
never becomes an attack surface against L2.

## 2. Assumptions and Scope

PoB's security rests entirely on the security of the L1 ledger. A flaw in that ledger
propagates straight into L2. Two conditions therefore constrain the choice of L1:

- **L1 must be a PoW public chain.** PoB's objectivity comes from costs being
  irrevocable, which requires the underlying ledger to be built on irrevocable costs
  as well.
- **L1 must have adequate scripting.** Miners' prepayments and their per-height
  payment commitments are held on L1, which must be able to express constraints such
  as "an entry, once written, can never be altered" and "the prepaid total only ever
  grows". An L1 with limited scripting — Bitcoin, for instance — cannot carry PoB's
  payment layer.

CKB satisfies both, and its design intent is to serve L2s in the first place, making
it the most natural host for PoB. PoB is nonetheless a general protocol and does not
exclude any other L1 meeting those conditions.

The rest of this document assumes CKB as L1 and a vertical application chain as L2.

## 3. Terminology

| Term | Meaning |
| --- | --- |
| L1 / parent chain | The base chain supplying ledger security, finality and scripting |
| L2 / child chain | The application chain mounted on L1, reaching consensus through PoB |
| mining addr | L2's receiving address on L1, where miners' block payments flow |
| `payment` | The amount of L1 token a miner declares for one L2 height, submitted as a commitment |
| `vrf_output` | The VRF output a miner derives from a fixed input using its block-producing key |
| `goal` | The competition score, `goal = f(payment, vrf_output)` |

## 4. Protocol Structure

PoB has three layers, each solving one independent problem:

```
┌──────────────────────────────────────────────────────────────────┐
│  Admission   Who is eligible to mine                             │
│              Holding L1 native tokens suffices; no registry      │
├──────────────────────────────────────────────────────────────────┤
│  Production  Who produces the block at a height                  │
│              goal = f(payment, vrf_output), one score per block  │
├──────────────────────────────────────────────────────────────────┤
│  Finality    Which fork is canonical, and when it is final       │
│              Headers anchored in fixed L1 windows per batch;     │
│              once a window closes, the complete continuous run   │
│              with the largest cumulative goal                    │
└──────────────────────────────────────────────────────────────────┘
```

## 5. Admission

Holding L1 native tokens is the only threshold for taking part. The protocol keeps no
miner registry and defines no on-chain delegation — retail holders entrusting tokens
to a miner is an arrangement made in the real world, not a protocol component.

Leaving the admission layer empty is deliberate. Any on-chain whitelist or delegation
contract introduces state that must be governed, whereas PoB's security comes from the
payment itself, never from identity.

## 6. Block Production

### 6.1 The Competition Rule

The right to produce a block at each height goes to the largest `goal`:

```
goal = f(payment, vrf_output)
```

`payment` is the amount a miner declared on L1 for that height; `vrf_output` is what
the miner gets by evaluating the VRF over the previous block hash with its own
block-producing key. Multiplying the two is the simplest form of `f`.

**Payment exists to introduce cost.** Block production must cost something — that is
the precondition for consensus to be objectively verifiable: an attacker who wants to
attack L2 has to put up the same hard money as an honest miner, rather than having
nothing at stake as in PoS. More importantly the cost is irrevocable **expenditure**,
not a lockup: however deep an attacker's pockets, every attack shrinks them, and it
cannot sustain the same weight at every height.

**Payment also builds a centre of scale.** A public chain needs a degree of scalable
centralisation, the role played by mining pools, farms and staking agents. With block
producers numbering in the millions, uncles and orphans would proliferate, the cost of
a 51% attack would fall rather than rise, and the network would congest. PoB lets the
act of "willing to pay" select this centre naturally, and the centre stays fluid,
depending on no registration or permission.

**The VRF exists to stop the richest from monopolising.** Ranking by payment alone
would park block production permanently with the deepest pockets. Weighting the score
by a pseudorandom value markedly weakens short-term monopoly. The VRF supplies three
necessary properties: its output is unpredictable to others, so outcomes cannot be
foreseen; it is uniquely determined by a fixed key and input, so a miner cannot grind
for a better result; and it is cheap to verify, so the whole network can check it
instantly.

### 6.2 Identity Binding

The VRF key must be the block-producing key itself, and verification uses the
block-producing public key carried in the block rather than a separate VRF key. One
key serves three roles at once: signing L2 blocks, generating the VRF output, and
holding the paying account on L1.

This single constraint closes off two kinds of cheating: a miner cannot mint a pile of
throwaway VRF keys and sift for a favourable output, and it cannot appropriate someone
else's payment record for its own block.

### 6.3 The Production Flow

```
  Miner, locally                        Network
  ──────────────                        ───────
  1. Read the payment already committed on L1 for this height
  2. vrf = VRF(sk, prev_block_hash)
  3. goal = f(payment, vrf)
  4. Pack transactions, assemble the block
     The block carries (vrf_output, vrf_proof,
              payment commitment, allocation proof, goal)
  5. Broadcast ───────────────────────▶  6. Check the candidate item by item:
                                            · VRF proof holds under the block key
                                            · Payer identity == producer identity
                                            · Allocation proof holds
                                            · Recompute goal
                                         7. Adopt the heaviest continuous fork
```

## 7. The Payment Layer

### 7.1 The Block Interval Mismatch

L2's block interval is usually shorter than L1's. If a miner only sends its payment
transaction to L1 just before competing, that transaction has not yet landed when the
L2 block is produced, and L2 has no way to tell who paid more. Left unsolved, this
pins L2's block interval to L1's, and the design falls back to PoS plus BFT.

### 7.2 Prepayment and Allocation

PoB uses prepayment plus a zero-knowledge allocation proof:

```
  Cycle start    The miner pays L1 tokens to the mining addr; the total A
                 is publicly visible. In the same move it writes down, once
                 and for all, how that money is split across heights, with a
                 zero-knowledge proof that a_0 + a_1 + ... + a_n == A
                               │
  L1 check       The proof is verified against the public A and the per-height
                 commitments; failing it, the table cannot be written at all,
                 so any table on chain is a balanced one
                               │
  Each block     Declare which row of the table this block draws on (nothing
                 is really paid on L2 — the money is already on L1); the
                 network feeds (vrf_output, a_h) into goal
```

**The total is public; each height's amount must be hidden.** The total `A` is a real
L1 transfer, already visible on chain, and there is no need to hide it — it says how
much this miner is prepared to commit, not how much it bids at any given height. What
must be hidden is `a_h`: if competitors can see in advance what you bid for a height,
they can adjust accordingly and the timing protection of §7.3 comes to nothing.

The zero-knowledge proof therefore takes the public `A` as input, convincing the
network that "this table splits A exactly" while revealing no individual `a_h`.

**Equality rather than "no more than".** The money is already spent; whatever goes
unallocated is not refunded either, so demanding the table balance asks nothing extra
of the miner, and it reads more cleanly: the table is the whole account of where the
money went. The price is that a miner plans a whole cycle at once; topping up means
opening another cycle and balancing another table.

**Every amount must be proven in range.** A zero-knowledge proof computes over a finite
field, where numbers wrap around: unconstrained, a miner could write a "negative"
amount at one height to inflate the others, and simply never reveal that height. So
besides "the sum equals A", the proof also bounds every `a_h` to a legal range.

### 7.3 Payment Must Come First

If a miner could decide how much to pay after seeing everyone else's scores, whoever
broadcasts last would enjoy a natural advantage: everyone would stall, watch the rival
`goal`s, and work backwards to the payment needed to overtake them. Consensus would
degenerate.

The correct ordering is: **commit the payment for this height on L1 first, and only
then compute the VRF.**

```
  ✗  compute VRF → watch rivals' goal → back out a payment → broadcast
  ✓  commit payment on L1 → compute VRF → compute goal → broadcast
```

Under this ordering, `payment` is locked before any competitive information is
visible, and `vrf_output` is uniquely determined by a fixed input. Neither input can
be adjusted, which makes the outcome both fair and random.

**The lead time is roughly 4 minutes, that is 24 L1 blocks.** The figure is set by
what selfish mining requires; see 9.3.

## 8. Final Consensus

### 8.1 Anchoring and Fork Choice

Every L2 block's **header** goes to L1 in the clear. Once the header is in an L1
block, the L1 height it sits at is the evidence that this L2 block "was there at the
time". Full nodes read the header off L1 and recompute the block hash themselves, so
they know which L2 block the record belongs to without anyone having to tell them.

The whole header goes on chain rather than just the block hash so that L1's record
stands on its own: height, parent link, producer, VRF output and payment are all in
the header, so anyone reading only L1 can reconstruct every height's `goal` and the
shape of the forks, and the block hash is recomputed from the contents rather than
taken from whatever the header claims.

**Submitting a header takes no identity: anyone may submit one for any L2 block.**
This does not conflict with the identity binding of 6.2. That constraint governs *who
bought the height* — payer, producer and signer must be one key, judged by L2 nodes
from the block's own contents. Submitting a header only stamps it with which L1 block
it sits in, and who applies the stamp does not change what is under it.

Nor does a submitter have room to cheat. The header is fixed by the block and signed
by its producer: the submitter cannot alter any part of it, and altering it yields a
different hash. It can neither pass someone else's block off as its own — the producer
is named in the block, bound there by the payment and the VRF — nor conjure a block
from nothing, since writing bytes is easy but producing a valid block that passes the
checks is not. So the chain need not check a submitter's identity: there is nothing to
check, and nothing to be gained by lying.

The same block may therefore be submitted by several parties, appearing on L1 as
several identical submissions. They do not conflict: each is a legitimate anchor for
that block, and whichever landed first inside the window is the block's timestamp.

**Anchoring goes into fixed windows, batch by batch.** L2 genesis corresponds to some
L1 height `n`, written into the genesis block as part of what defines the chain. L2 heights are grouped `b` at a time: batch `i` is heights `i·b+1`
through `i·b+b`. Batch `i`'s headers count only in L1 blocks `n+i` through `n+i+k`, and
a submission landing outside that window is ignored. Windows step forward one L1 block
at a time, so neighbouring batches' windows overlap. `b` is chosen from the L1 and L2
block rates so that, on average, one batch corresponds to one L1 block.

`k` is a chain-quality parameter: any `k` consecutive L1 blocks include one from an
honest producer willing to pack the batch's headers. So whenever honest miners have
produced a complete batch, it is certain to land inside its window.

**A batch is decided only after its window closes.** Once L1 passes `n+i+k` and gathers
`d` more confirmations, the window's contents can no longer change, and the network
decides batch `i`: among the headers anchored in the window, it considers only the
branches that hang off batch `i-1`'s decided tip, are linked block to block, and cover
all `b` heights, and **takes the one whose `b` blocks have the largest cumulative
`goal`.**

None of the three conditions can be dropped. **Cumulative** means comparing the sum
over the whole batch, not who has the higher `goal` at some single height.
**Continuous** means every block names the previous one as its parent — you cannot
cherry-pick the best block at each height and splice them together. **Complete** means
a branch missing any height does not compete: given how `k` is chosen, a complete batch
honest miners finished always lands, so a branch with a gap is one the network did not
finish, not one that lost. Equal totals go to the branch whose block hash is smaller at
the first height where the branches part.

The decision reads only the headers on L1. Every node reads the same window and runs
the same checks, so every honest node necessarily arrives at the same canonical chain,
whichever fork it happened to follow locally beforehand.

The VRF output inside `goal` is hard to forge, and every block is backed by a real L1
payment, which makes `goal` an objectively verifiable number. Anyone can compare scores
to determine which fork to follow, with no voting and no extra communication rounds.

**The window makes "late reversal" fail outright.** A miner that sits on its hands and
only later produces a higher-scoring batch can only land its headers outside a window
that has long since closed, where they are not compared at all. A fork bought after the
fact, however much it paid, cannot produce headers that were in the window at the time.

### 8.2 Division of Labour

**L1 backs up, L2 decides.** L1's job is to keep an immutable backup of the canonical
chain that has already played out, and nothing besides — it does not verify what a
header says, nor can it scan every bid at a height, so it is in no position to decide
anything. L2 nodes submit and decide: write headers to L1 before the window closes,
read back every header in the window once it has, and take the complete continuous
branch with the largest cumulative `goal`.

**The backup is what identifies a latecomer.** Score alone does not stop this attack: a
large L1 holder spends enough money after the fact to buy every block after some
height, builds a higher-scoring fork, and rolls back a canonical chain that had long
since settled. By score alone, a chain that existed at the time and a chain fabricated
afterwards look identical.

L1's backup supplies the missing distinction: each batch's headers count only in its
window, and the window is a stretch of L1 that has passed and cannot be written to
again. A fork fabricated afterwards can only land its headers in recent L1 blocks —
**the question is not whose score is higher, but whose history was actually there at
the time.**

What makes this division work is that deciding, although it happens on L2, carries no
subjective element: each block's score is uniquely determined by its payment on L1 and
its VRF, a batch's cumulative score is one summation, continuity and completeness are
plain to see, and the window is a public range of L1 blocks. Honest nodes looking at the
same L1 necessarily arrive at the same canonical chain — objectivity comes from scores
being verifiable, resistance to after-the-fact reversal from that backup on L1, and
neither asks L1 to compute anything.

For the concrete shape this takes on CKB, see [ckb_layout.md](ckb_layout.md).

### 8.3 Why Anchoring Matters in the Long Run

After the protocol has run for a long time, the mining addr accumulates a substantial
pile of L1 tokens. Should whoever controls it eventually amass enough to overturn the
chain, rewriting history becomes theoretically possible. Continuously anchoring every
height's block header to L1 nails the history that has happened to a chain with
stronger security, leaving no long-range attack any room. This is the protocol
constraining its own future — and it is the backup of 8.2 doing the work: the
comparison is not whose score is higher, but whose history was actually there.

What is anchored is the header in the clear, so L1 is itself a complete history: a
newly syncing node reading only L1 gets every header ever anchored at each height, when
each first landed, and its `goal` — everything fork choice needs, without relying on
any peer to relay it faithfully. Transaction bodies still come from peers, but the
transaction root in the header binds them, so a substituted one does not match.
Forging history is impossible, and withholding it has nothing to grip.

### 8.4 No BFT

BFT is, at bottom, deciding finality by subjective vote. Only a system where block
production is free and objective constraints are absent is forced to fall back on
human voting to choose a fork. In PoB the L1 payment is a large and objective cost
constraint that miners can read the canonical chain from directly; layering BFT on top
is redundant, and buys nothing but higher network and engineering complexity.

Finality time is fixed: batch `i` is decided when L1 reaches `n+i+k+d`. Where a
particular deployment needs shorter confirmation times, `k` and `d` can be reduced as
far as L1's chain quality allows, still with no voting.

## 9. Attack Surface and Defences

### 9.1 Monopoly by the Rich

Competing on payment alone would hand block production permanently to the deepest
pockets. VRF weighting turns a money advantage into a probabilistic edge only, never a
deterministic one.

### 9.2 Last-Broadcaster Advantage

See 7.3. Committing payment ahead of time locks both sides' inputs before either can
observe the other.

### 9.3 Selfish Mining

Selfish mining directly on L2 does not work: only the VRF output and the payment decide
block production, the former uniquely determined for a given miner and the latter
already locked on L1. There is no hashpower to withhold and release at a chosen moment.

The attack can only be mounted from L1. Two blocks may coexist at the same L1 height,
and an attacker can submit payment commitments for the same L2 height on both L1 forks.
Until the L1 fork converges nobody can tell which side will become canonical, and the
uncertainty in L1's finality infects L2's.

Moving the payment commitment 24 L1 blocks (about 4 minutes) earlier removes this
window: that depth already provides enough probabilistic certainty that by the time L2
uses a commitment, the L1 fork it sits on converged long ago.

### 9.4 A Sybil Attack by the Operator

The mining addr continuously absorbs the tokens miners pay, which puts the L2 operator
in a peculiar position: if it mines itself, it pays itself, incurring no real cost
beyond L1 fees, while other miners keep feeding it tokens.

The VRF only guarantees that paying more does not guarantee winning; it does nothing
against a Sybil attack. The operator can appear as thousands of miners at once and
dilute honest miners' chances without limit.

The defence is to mark tokens leaving the mining addr irreversibly:

```
     miner payment ─────────▶  mining addr
                                    │
                    on the way out, the script writes a constraint:
                    these tokens can never return to the mining addr
                                    │
              ┌─────────────────────┴─────────────────────┐
              ▼                                           ▼
    usable for development, operations           unusable for mining
    and ecosystem grants                         one's own chain
```

The constraint is fixed in the token's type script, and the operator cannot evade it by
mixing or otherwise erasing transaction history. The only detour is to trade marked
tokens on the market for ordinary ones, but marked tokens have restricted uses and
generally trade above one-to-one, so the operator must give up more than it gets back
for attacking — which does not hold up. And the more valuable L2 becomes, the worse the
rate and the higher the cost of attacking.

### 9.5 Long-Range Attacks

See 8.3. History already anchored to L1 cannot be rolled back.

### 9.6 L1 Miners Censoring L2 Blocks

An L2 block's header must be packed by an L1 block producer to reach the chain — the
unavoidable price of depending downward on L1. This is an attack surface that L1
decentralisation does not shrink: however many pools L1 has, exactly one of them
produces any given block. If that producer also mines on L2, it can pack its own
header and drop its rivals'. Decentralisation merely means each pool lands in that
seat less often; it does not weaken the motive once it is there, because the payoff is
certain.

The payoff has two layers. **Dropping rivals' headers selectively**, held past the
rivals' window, leaves their branch incomplete and out of the running, so the censor's
own fork becomes canonical and it collects the block rewards and fees. **Dropping every
header indiscriminately** is harsher: held for a whole window, it leaves that batch with
no complete branch and L2 finality stands still — no longer a question of who wins, but
of liveness.

Headers go on chain in the clear, so the producer can tell which submission is a
rival's. This censorship is therefore not stopped by keeping it blind; what bounds it
is the following:

- It has to succeed on every L1 block of the window in a row — `k+1` consecutive L1
  producer seats. `k` is chosen by chain quality precisely so that any `k` consecutive
  L1 blocks include an honest producer, who packs the censored header. Miss one block
  and the header is in the window, and resending costs nothing.
- And the resender need not be the original. Submitting a header takes no identity
  (8.1): anyone may submit for any block — the censored miner from a fresh address,
  another miner, or any full node looking on. What the censor has to stop is therefore
  not a set of addresses but everyone on the network who might resubmit.
- It is visible on chain — an L2 block has long been circulating on the L2 network
  while its header never makes it into L1, and the L1 blocks of that period carry only
  the censor's own submissions.
- CKB splits transactions into proposal and commitment, and blocks reference their
  uncles' proposals; a transaction that lands in a block that loses the race still has
  its proposal enter the main chain and can be committed in a later block. A submission
  missed for network reasons is usually delayed, not lost.

So this defence is exactly as strong as `k`: while the chain-quality assumption holds,
a censor cannot fill a window, and a rival's header always lands before the window
closes. Once a header is in a block, that block carries its timestamp, and excluding it
afterwards means rolling L1 back — an attack on the L1 ledger itself, outside L2's
trust assumptions (section 2).

## 10. Economics

### 10.1 Tokens Are Not Burned

One intuitive move is to burn the L1 tokens miners pay, manufacturing deflation. PoB
does not, because the protocol's aim is to let a great many application chains run as
L2s on L1 over the long term, and at that scale burning has three consequences:

- When burning outpaces L1 issuance, it destroys L1 wealth outright and L1 faces a
  liquidity drought.
- When burning does not outpace issuance, it is redistribution, which forces the
  question of who the newly issued tokens should belong to — and sending tokens
  straight to a fixed address is itself one special case of that redistribution.
- Once deflation lifts the token price, holders grow less willing to spend tokens
  mining on L2, and the security budget of L2's consensus falls steadily instead.

Tokens therefore flow to the L2 operator, and are not locked away permanently: they are
liquid, and they cover L2's development and operating costs. The incentive to misbehave
that this creates is constrained by the mechanism in 9.4.

### 10.2 Block Rewards

Miners who lose the competition also receive some amount of the L2 native token as
compensation, much like the compensation paid to uncle block producers. Taking part is
therefore not a winner-take-all, loser-gets-nothing game.

### 10.3 The Value Loop

```
        L2 application value rises
              │
              ▼
   L2 fee revenue rises; the native token is worth more
              │
              ▼
   More L1 holders are willing to spend tokens to mine on L2
              │
              ▼
   Buying pressure on the L1 token rises; the L1 token is worth more
              │
              └──────────▶ (back to the start)

   The reverse holds as well: no value on L2 → a worthless native token →
   nobody willing to invest → the chain clears out naturally
```

PoB is therefore not a drain on L1 but a channel carrying L2's application value back
into it.

### 10.4 Structural Differences from PoS

**Cost structure.** PoS costs almost nothing to start, which makes it easy to push the
price up cheaply early in a bull market, but credibility and price are extremely hard
to recover after a fall, and pumping depends heavily on exchanges and market makers.
PoB's cost is real, irrevocable expenditure; security does not decay several-fold with
short-term price swings, nor can it be over-leveraged by derivative protocols of the
restaking sort.

**Distribution path.** In conventional PoS the operator issues a token, users buy it on
an exchange, then lock it up in staking — the exchange takes a cut twice, the operator
never sees enough cash flow, and users hold an illiquid asset while carrying the
downside. In PoB miners deal with the operator directly, funds arrive directly, and the
L2 native token miners receive is fully liquid and usable immediately for anything.

**Objectivity of consensus.** PoS needs a BFT-family protocol to complete fork choice,
and BFT voting is not objectively verifiable consensus; both engineering and network
propagation complexity are high. PoB's fork choice is a comparison of numbers.

## 11. Block Lifecycle

```
  [PRE-COMMITTED]  Payment commitment is on L1 with 24 L1 confirmations
         │
         ▼
  [PROPOSED]       Compute VRF and goal, assemble the block, broadcast
         │
         ▼
  [VERIFIED]       The network checks VRF proof, identity binding and the
                   allocation proof, and recomputes goal
         │
         ▼
  [ADOPTED]        Adopt the heaviest continuous fork locally, execute the
                   transactions and persist
         │
         ▼
  [ANCHORED]       The block header goes to L1 in the clear and lands inside
                   its batch's window [n+i, n+i+k]
         │
         ▼
  [FINALIZED]      L1 passes n+i+k+d; the network reads the window and decides
                   the complete branch with the largest cumulative goal
         │
         ▼
  [FOLLOWED]       Nodes reconcile the local chain against L1's record of
                   headers, rolling back and switching on a mismatch
```

## 12. Open Questions

### 12.1 How Fast L1 Storage Is Consumed

Every L2 block has to leave a trace on L1, and a CKB cell locks capacity at 1 CKB per
byte, for the long term. At a 3-second L2 block interval, the cells needed for
anchoring alone would lock up millions of CKB per day, accumulating over time.

This bears directly on the argument in 10.1, which holds that L1 tokens should not be
burned on the premise that PoB can carry **many** application chains over the long run.
If every L2 chain consumed L1 state space at that rate, the premise would not stand.

Known directions for relief:

- **Batched anchoring.** One cell commits to a Merkle root over a range of heights
  instead of one cell per height. Permanence is unaffected — the root is on chain and
  any height can be proven by its path — while occupancy drops from proportional to the
  number of heights to proportional to the number of batches.
- **Progressive folding.** Once a period closes, fold its result into a single
  long-lived accumulator cell, keeping occupancy constant.
- **Retrospective compaction.** Let anyone merge several past cells into one new cell
  committing to all of their content, taking the released capacity as payment. This
  needs no batching planned in advance and carries its own incentive.

All three depend on the same premise: that L2 nodes can accept "by proof" rather than
"by direct read" when querying history. That needs confirming along L2's read path.

> As far as CKB goes, the shape adopted in [ckb_layout.md](ckb_layout.md) has dissolved
> this problem: each height leaves one block header (at most 4 KB) on L1, and the cell
> carrying it is short-lived, its capacity reclaimed by the miner once the dust settles;
> the header itself stays in the transaction, permanently readable, without occupying
> cell capacity. No long-lived state accumulates with height; occupancy is O(1). The pressure described
> in this section only appears in a design that leaves one permanent cell per height.

### 12.2 Others

- **L1 and L2 reorganising together.** Both run Nakamoto consensus, and in the extreme
  case where both reorganise at once, the follow rule needs stating more precisely.
- **Confirmation latency.** A batch waits `k+d` L1 blocks before it is final, which
  constrains low-latency use cases. How small `k` and `d` can go depends on L1's chain
  quality and reorg depth; the safety margin has yet to be quantified.
- **The concrete form of `f`.** Multiplication is the simplest form; whether a weighting
  function more resistant to a money advantage exists is worth exploring.
