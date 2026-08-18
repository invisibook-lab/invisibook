# Invisibook Documentation

> **Status:** Current (2026-08-17). This file is the index. Start here.

## Reading order

1. [papers/invisibook.pdf](../papers/invisibook.pdf) — the protocol
   paper (NDSS 2026 submission). The normative design.
2. [paper_deviations.md](paper_deviations.md) — **every place the code
   deviates from the paper**, why, and with what effect. Read this
   before you trust either the paper or a design doc.
3. [settlement_protocol.md](settlement_protocol.md) — the settlement
   protocol step by step: what trader A and trader B each do and
   submit, with the full constraint list of every MPC check and ZK
   relation.
4. The component designs: [chain_design.md](chain_design.md),
   [zk_design.md](zk_design.md), [cozk2p_design.md](cozk2p_design.md),
   [app_design.md](app_design.md).

## Document catalog

| Document | Language | Status | Content |
|---|---|---|---|
| [paper_deviations.md](paper_deviations.md) | EN | **Current** | Implementation vs. the paper, item by item (D1–D17) |
| [settlement_protocol.md](settlement_protocol.md) | EN | **Current** | The settlement protocol step by step: A/B walkthroughs, sequence diagrams, exact submissions, every MPC/ZK constraint |
| [chain_design.md](chain_design.md) | EN | **Current** | L2 chain: tripods, note pool, matching, compare gate, atomic `SettlePair` |
| [zk_design.md](zk_design.md) | EN | **Current** | Note primitives (golden spec), Groth16 circuit catalog, binds, proving/verifying toolchain |
| [cozk2p_design.md](cozk2p_design.md) | EN | **Current** | 2-party SPDZ + collaborative PLONK compare session, stdio protocol, trust caveats |
| [app_design.md](app_design.md) | EN | **Current** | Wallet stores, note-based order placement, two-phase settlement driver, crash recovery |
| [cozk_experiments.md](cozk_experiments.md) | EN | **Current** (record) | Measurements: cost of the cryptography, effect of the round-trip time, one complete trade — each with the command that reproduces it |
| [settlement_hardening_plan_zh.md](settlement_hardening_plan_zh.md) | ZH | **Current** (plan) | rev.4 hardening plan (F1–F4) with the implementation-status table (§六点五) |
| [spdz_itmac_theory_zh.md](spdz_itmac_theory_zh.md) | ZH | **Current** (notes) | SPDZ / IT-MAC theory study notes |

Binary assets: `invisibook_protocol.pdf` (early protocol sketch),
`invisibook_desktop.png`, `logo.png`.

## Conventions

These rules keep the set consistent; follow them when you add or edit a
document.

1. **Status banner.** Every document carries a
   `> **Status:** Current (date) …` or `> **Status:** Historical …`
   blockquote directly under its H1. Historical documents say what
   superseded them and must not be used as a reference for new code.
2. **Language.** Design documents are English. Chinese documents carry
   the `_zh` suffix and are plans or study notes, not normative
   designs.
3. **Paper alignment.** A design document does not restate paper
   arguments; where it differs from the paper it links the matching
   `D#` item in [paper_deviations.md](paper_deviations.md). New
   deviations get a new `D#` entry in the same change.
4. **Terminology.** One name per concept, everywhere:
   *note* (a shielded pool UTXO), *note opening* (`(sk, token, v, r)`),
   *order opening* (`(q, locked_amount, r_locked)`),
   *collateral commitment* (`Order.LockedCommitment` — the order's
   ONLY commitment, locked-only model, D17),
   *compare gate* (`SubmitCompareCoZk2p` /
   `SubmitCompareCoZk`), *two-phase settlement* (compare anchored on
   chain before any reveal — F1), *settle leg* (one side's signed
   settle proof), *atomic `SettlePair`* (both legs in one writing —
   F2). F1/F2/F3/F4 always refer to the rev.4 findings in
   [settlement_hardening_plan_zh.md](settlement_hardening_plan_zh.md).
5. **Numbers live in one place.** Measurements go into
   [cozk_experiments.md](cozk_experiments.md) with the command that
   makes them ([../experiments](../experiments)); other documents cite
   it instead of embedding numbers.
6. **Dev caveats are loud.** Anything that voids a security guarantee
   (mock Beaver, dev SRS, plaintext rendezvous, blind bridge) is
   labeled dev-only where it is described, and listed centrally in
   [cozk2p_design.md](cozk2p_design.md) §5 and
   [paper_deviations.md](paper_deviations.md) §2 (D9–D13).
