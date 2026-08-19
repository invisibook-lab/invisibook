# Protocol result comparison

Old: **XOR full-proof**. New: **native final-KZG SPDZ share**.

Change is `(new - old) / old`; a negative percentage is a reduction. Missing measurements are shown as —.

## RQ1 — cryptographic session

| median total | old (ms) | new (ms) | change |
|---|---:|---:|---:|
| single prover | 425.07 | 480.80 | +13.11% |
| two-party in-process | 3,962.34 | 4,016.72 | +1.37% |
| two-party QUIC | 5,150.06 | 4,936.51 | -4.15% |

| comparison material per party | old (B) | new (B) | change |
|---|---:|---:|---:|
| compressed proof / native share | 769 | 771 | +0.26% |

The old value is the compressed standard-proof length (an XOR share has the same length); the new value is the compressed native final-KZG SPDZ share.

| traffic per trader | old (B) | new (B) | change |
|---|---:|---:|---:|
| A → B | 65,466,086 | 65,201,409 | -0.40% |
| B → A | 64,277,160 | 63,917,197 | -0.56% |
| both directions | 129,743,246 | 129,118,606 | -0.48% |

| protocol-specific phase (not directly comparable) | in-process (ms) | QUIC (ms) |
|---|---:|---:|
| old `open_ms` | 2,268.73 | 3,160.52 |
| new `share_export_ms` | 2,388.70 | 3,239.56 |

`open_ms` reconstructed/opened the old proof, whereas `share_export_ms` exports an unopened native share. No percentage is calculated between them.

## RQ2 — network RTT

| RTT (ms) | old median total (ms) | new median total (ms) | change |
|---:|---:|---:|---:|
| 0 | 6,659.61 | 6,209.68 | -6.76% |
| 10 | 17,734.04 | 14,712.51 | -17.04% |
| 30 | 30,234.27 | 22,475.62 | -25.66% |
| 60 | 35,486.33 | 42,886.27 | +20.85% |
| 100 | 52,532.73 | 47,488.87 | -9.60% |

| RTT (ms) | old `open_ms` | new `share_export_ms` |
|---:|---:|---:|
| 0 | 4,929.53 | 4,490.68 |
| 10 | 13,486.88 | 10,520.21 |
| 30 | 21,026.70 | 13,483.10 |
| 60 | 18,844.27 | 26,711.40 |
| 100 | 26,277.43 | 20,451.70 |

The two phase columns above are protocol-specific and are not used to compute a change percentage.

## RQ3 — end-to-end trade

| metric | old | new | change |
|---|---:|---:|---:|
| full trade median (ms) | 34,478.36 | 35,187.14 | +2.06% |

### Semantic critical-path phases

| phase | old median (ms) | new median (ms) | change |
|---|---:|---:|---:|
| rendezvous | 4,019.47 | 4,019.84 | +0.01% |
| comparison | 11,544.84 | 10,081.72 | -12.67% |
| settlement proof | 164.82 | 121.46 | -26.31% |
| final settlement | 4,476.62 | 6,309.32 | +40.94% |
| total | 19,856.47 | 20,497.60 | +3.23% |

### Chain verification

| verifier | old median (ms) | new median (ms) | change |
|---|---:|---:|---:|
| `send_order` | 5.27 | 5.35 | +1.58% |
| `settle_cozk2p` | 11.97 | 12.46 | +4.02% |
| `settle_large` | 5.12 | 4.99 | -2.61% |
| `settle_small` | 4.84 | 4.84 | -0.01% |

### On-chain payload

| metric | old | new | change |
|---|---:|---:|---:|
| comparison share per submission (B) | 1,983 | 2,008 | +1.26% |
| comparison-share submissions per trade | 2 | 2 | +0.00% |
| comparison shares per trade (effective B) | 3,966 | 4,016 | +1.26% |
| all effective on-chain payload per trade (B) | 11,517 | 11,567 | +0.43% |

Comparison writing: old `SubmitCompareCoZk2pShare`, new `SubmitCompareCoZk2pShare`.

| RQ3 protocol-specific session phase (not directly comparable) | Alice (ms) | Bob (ms) |
|---|---:|---:|
| old `open_ms` | 3,894.07 | 3,890.92 |
| new `share_export_ms` | 2,772.12 | 2,703.52 |
