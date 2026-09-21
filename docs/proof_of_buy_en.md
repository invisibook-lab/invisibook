# Proof of Buy

A Layer 2 consensus protocol designed around a Layer 1.

> [中文版](proof_of_buy.md)

## 1. Overview

Proof of Buy (PoB) buys the right to produce L2 blocks with **money actually spent
on L1**, in place of **coins locked up on L2**. A VRF weights each payment randomly
to decide the winner at every height; the block header and its competition score are
then anchored back to L1 as a commitment, where L1 keeps a backup of that history and
confers finality on it.

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
│              Heaviest continuous fork by cumulative goal;        │
│              commitments anchored to L1                          │
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
                 is publicly visible
                               │
  Each block     Declare the amount a_h this block draws (nothing is really
                 paid on L2 — the money is already on L1), together with a
                 zero-knowledge proof that a_0 + a_1 + ... + a_h ≤ A
                               │
  Verification   Anyone verifies that proof against the on-chain A as public
                 input, then feeds (vrf_output, a_h) into goal
```

**The total is public; each height's amount must be hidden.** The total `A` is a real
L1 transfer, already visible on chain, and there is no need to hide it — it says how
much this miner is prepared to commit, not how much it bids at any given height. What
must be hidden is `a_h`: if competitors can see in advance what you bid for a height,
they can adjust accordingly and the timing protection of §7.3 comes to nothing.

The zero-knowledge proof therefore takes the public `A` as input, convincing the
network that "the declared amounts sum to no more than what was actually paid" while
revealing no individual `a_h`.

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

Every L2 block goes to L1, but **not in the clear — as a commitment**
`SHA256(block_hash || random)`. Once the commitment is in an L1 block, the
submitter broadcasts the opening over the L2 network; full nodes hash
`(block_hash, random)` to check it reproduces the commitment on chain, and only
then does the content become public.

The block hash is all that needs committing to: it already determines the whole
block — height, `goal`, VRF output, parent link, every transaction — so binding
any of those in alongside it would commit to the same facts twice.

**Two-phase submission exists to stop L1 miners from censoring L2 blocks.** An L2
block's commitment has to be packed by an L1 block producer to reach the chain. Were
it submitted in the clear, the L1 miner producing that block could see which L2 blocks
worked against it and drop them. As a commitment, all it sees is a structureless hash,
with nothing to select on. The reasoning is in 9.6.

This changes nothing about fork choice: once a commitment is in a block, both its
content and the L1 height it sits at are fixed, and revealing merely reads out a value
that was already locked.

Several forks may be submitted for the same L2 height. The fork choice rule is: **take
the fork with the largest cumulative `goal` whose blocks are continuous.**

Neither condition can be dropped. **Cumulative** means comparing the sum of scores
along a whole branch, not who has the higher `goal` at some single height.
**Continuous** means the branch has a block at every height from the fork point on,
with no gaps — you cannot cherry-pick a few high-scoring blocks and splice them into a
chain.

The cumulative rule makes "late reversal" fail by itself. A miner that sits on its
hands and only later produces a block with a very high `goal` ends up with a branch of
length one. To outweigh the canonical chain it must produce every block after that
point itself, paying real L1 tokens for each. **To rewrite history you have to buy
history again.** This is the same logic as "rewriting history means redoing the work"
in Nakamoto consensus, with the cost denominated in real payment rather than hashpower.

The VRF output inside `goal` is hard to forge, and every block is backed by a real L1
payment, which makes `goal` an objectively verifiable number. Anyone can compare scores
to determine which fork to follow, with no voting and no extra communication rounds.

**That rule is the finality rule; there is no second gate.** No threshold says how
many blocks deep something has to be before it counts — as in Nakamoto consensus,
irreversibility grows with the gap in cumulative score: to overturn a chain you have
to buy the gap back, and the wider it is the less affordable that becomes.

What L1's backup shuts down is the other route. By score alone, a chain that existed
at the time and a chain bought afterwards look identical; but every block of the
original had its commitment written into L1 as it happened, while a fabricated fork
can only carry commitments that appeared recently. Comparing against L1's record is
what tells them apart — see 8.2.


### 8.2 Division of Labour

**L1 backs up, L2 decides.** L1's job is to keep an immutable backup of the canonical
chain that has already played out, and nothing besides — it cannot see what a
commitment contains, nor scan every bid at a height, so it is in no position to decide
anything. L2 nodes submit, reveal and decide: write commitments to L1, broadcast the
openings over the L2 network once included, check every opening they receive, and take
the heaviest continuous fork by cumulative `goal`.

**The backup is what identifies a latecomer.** Cumulative score alone does not stop
this attack: a large L1 holder spends enough money after the fact to buy every block
after some height, builds a fork with a higher cumulative score, and rolls back a
canonical chain that had long since settled. By score alone, a chain that existed at
the time and a chain fabricated afterwards look identical.

L1's backup supplies the missing distinction. Each block of the original chain had its
commitment written into L1 at the time, one by one, each carrying the L1 height it sat
at; a fork fabricated afterwards can only have commitments that appeared recently. L2
nodes recognise it by comparing against L1's record — **the question is not whose score
is higher, but whose history was actually there at the time.**

What makes this division work is that deciding, although it happens on L2, carries no
subjective element: each block's score is uniquely determined by its payment on L1 and
its VRF, a branch's cumulative score is one summation, and continuity is plain to see.
Honest nodes looking at the same blocks necessarily arrive at the same canonical chain
— objectivity comes from scores being verifiable, resistance to after-the-fact
reversal from that backup on L1, and neither asks L1 to compute anything.

For the concrete shape this takes on CKB, see [ckb_layout.md](ckb_layout.md).

### 8.3 Why Anchoring Matters in the Long Run

After the protocol has run for a long time, the mining addr accumulates a substantial
pile of L1 tokens. Should whoever controls it eventually amass enough to overturn the
chain, rewriting history becomes theoretically possible. Continuously anchoring every
height's bid commitment to L1 nails the history that has happened to a chain with
stronger security, leaving no long-range attack any room. This is the protocol
constraining its own future — and it is the backup of 8.2 doing the work: the
comparison is not whose score is higher, but whose history was actually there.

What is anchored is a commitment rather than plaintext, and that costs nothing in
force: commitments are binding, and nobody can produce a fake opening that matches the
one on chain. All an attacker can do is **withhold** — show a newly syncing node only
part of the openings, so that it computes a canonical chain with a lower cumulative
score. That requires the attacker to be that node's only source of data, and pulling
from several peers dissolves it. Forging history is impossible; withholding history can
be defended against.

### 8.4 No BFT

BFT is, at bottom, deciding finality by subjective vote. Only a system where block
production is free and objective constraints are absent is forced to fall back on
human voting to choose a fork. In PoB the L1 payment is a large and objective cost
constraint that miners can read the canonical chain from directly; layering BFT on top
is redundant, and buys nothing but higher network and engineering complexity.

Where a particular deployment needs shorter confirmation times, a more aggressive
finality rule can be agreed instead — treating a chain as irreversible once its
cumulative lead reaches some margin — still with no voting.

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

An L2 block's commitment must be packed by an L1 block producer to reach the chain —
the unavoidable price of depending downwards on L1. Here lies an attack surface that
does not weaken as L1 decentralises: however many pools L1 has, only one of them
actually produces the block at a given height. If that producer also mines on L2, it
can pack only its own commitment and drop its rivals'. Decentralisation merely means
each pool holds that position less often; it does nothing to weaken the incentive while
they hold it, because the payoff is certain.

The payoff has two layers. **Dropping rivals' commitments selectively** puts more of
the attacker's own blocks on the canonical chain, so its cumulative score pulls ahead
and it collects the block rewards and fees. **Dropping every commitment indiscriminately**
is worse: for as long as the blockade holds, those heights have no valid block
available at all and L2 stalls where it stands — no longer a question of who wins, but
of liveness. Left unchecked, L2 ends up at the mercy of L1 miners collectively.

Censorship presupposes **being able to see**: a producer must first tell which
submission works against it before it can drop that one selectively. Remove the
precondition and the attack collapses:

```
  Commit    The miner sends SHA256(block_hash || random) to L1
              │        The L1 producer sees a structureless hash, nothing more
              ▼
  Include   The L1 block packs the commitments it received
              │
              ▼
  Reveal    The miner broadcasts (block_hash, random) on the L2 network
              │        Full nodes check open(...) == the on-chain commitment
              ▼
  Choose    Among included and revealed blocks, take the heaviest
            continuous fork
```

An L1 producer faces a pile of mutually indistinguishable hashes and cannot tell which
belongs to a rival or which would erode its own cumulative lead, so selective dropping
has nothing to grip. By the time the reveal happens, the commitment was long since
fixed together with the L1 block holding it, and excluding it then would require
rolling back L1 — already an attack on the L1 ledger itself, outside L2's trust
assumptions (§2).

The defence introduces no new trust: one hash comparison between the opening and the
on-chain commitment, which any full node performs by itself, with no extra round of
interaction and nobody's word to take.

**What remains is indiscriminate censorship.** A producer recognises its own submission,
so it packs that one and drops all the rest. This differs from selective censorship in
kind:

- It has to succeed in every consecutive L1 block until the censored party gives up.
  Miss one block and the commitment is in, and resending costs nothing and can go on
  indefinitely.
- It is plainly visible on chain — one height with a single submission included, while
  every other miner holds a signed commitment that never landed. Selective dropping can
  pass for a network hiccup; a blanket blockade cannot.
- CKB splits a transaction into propose and commit phases, and blocks reference uncles'
  proposals, so even a transaction that lands in a losing block still has its proposal
  reach the canonical chain and can be packed in a later block. A submission missed for
  network reasons is usually delayed, not lost.

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
  [ANCHORED]       The commitment to the block hash goes to L1; its content
                   is invisible to the L1 producer
         │
         ▼
  [REVEALED]       Once included, the opening is broadcast on the L2 network;
                   full nodes check open(...) == the on-chain commitment
         │
         ▼
  [FINALIZED]      The score gap is past buying back, and L1's record
                   attests the chain was there at the time
         │
         ▼
  [FOLLOWED]       Nodes reconcile the local chain against L1's record of
                   commitments, rolling back and switching on a mismatch
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
> this problem: each height leaves only a 32-byte commitment on L1, and the cell
> carrying it is short-lived, its capacity reclaimed by the miner once the dust settles.
> No long-lived state accumulates with height; occupancy is O(1). The pressure described
> in this section only appears in a design that leaves one permanent cell per height.

### 12.2 Others

- **L1 and L2 reorganising together.** Both run Nakamoto consensus, and in the extreme
  case where both reorganise at once, the follow rule needs stating more precisely.
- **Confirmation latency.** Nakamoto finality latency constrains low-latency use cases.
  The short-cycle finality rule sketched in 8.4 is one direction, but its safety margin
  has yet to be quantified.
- **The concrete form of `f`.** Multiplication is the simplest form; whether a weighting
  function more resistant to a money advantage exists is worth exploring.
