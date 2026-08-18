//! Time each shielded-pool Groth16 circuit's rapidsnark prove + verify.
//! Usage: cargo run --release -p invisibook-lib --example bench_circuits

use std::time::Instant;

use invisibook_lib::{
    note::{asset_id, fr_from_be_bytes, note_commit, npk_from_sk},
    note_prover::{
        ClaimFeesWitness, NoteDepositWitness, SendOrderWitness, SettleLargeWitness,
        SettleSmallWitness, SpendSlot, SpendWithdrawWitness, prove_claim_fees, prove_note_deposit,
        prove_send_order, prove_settle_large, prove_settle_small, prove_spend_withdraw,
    },
    note_tree::NoteTree,
};
use zk::{setup::dev_setup_snarkjs, test_circuit::TestCircuitHandle};

fn rep(b: u8) -> [u8; 32] {
    [b; 32]
}

fn main() {
    let usdt = asset_id("USDT").unwrap();
    let eth = asset_id("ETH").unwrap();
    let sk = fr_from_be_bytes(&rep(0x43));
    let npk = npk_from_sk(sk);

    // A 3-leaf tree to spend from.
    let mut tree = NoteTree::new();
    tree.append(note_commit(npk, usdt, 40, fr_from_be_bytes(&rep(0x34))));
    let anchor = tree.root();
    let (path, bits) = tree.path(0);

    println!("circuit         setup_ms  prove_ms(mean of 3)  constraints_est");
    println!("-------------------------------------------------------------");

    // Each closure returns a boxed prove call producing () or panicking.
    macro_rules! bench {
        ($name:literal, $setup:expr, $prove:expr) => {{
            let t = Instant::now();
            let setup = dev_setup_snarkjs($setup).expect("setup");
            let setup_ms = t.elapsed().as_secs_f64() * 1e3;
            let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");
            let mut times = Vec::new();
            for _ in 0..3 {
                let t = Instant::now();
                ($prove)(&handle, &setup.zkey);
                times.push(t.elapsed().as_secs_f64() * 1e3);
            }
            let mean = times.iter().sum::<f64>() / times.len() as f64;
            println!("{:<15} {:>8.0} {:>20.0}", $name, setup_ms, mean);
        }};
    }

    bench!(
        "note_deposit",
        "note_deposit",
        |h: &TestCircuitHandle, z: &std::path::Path| {
            prove_note_deposit(
                NoteDepositWitness {
                    v: 2000,
                    r_bridge: fr_from_be_bytes(&rep(0x61)),
                    npk,
                    r_note: fr_from_be_bytes(&rep(0x62)),
                    asset: eth,
                    bind: fr_from_be_bytes(&rep(0x63)),
                },
                h,
                z,
            )
            .expect("prove");
        }
    );

    bench!(
        "spend_withdraw",
        "spend_withdraw",
        |h: &TestCircuitHandle, z: &std::path::Path| {
            prove_spend_withdraw(
                SpendWithdrawWitness {
                    slots: [
                        SpendSlot::real(sk, 40, fr_from_be_bytes(&rep(0x34)), path, bits),
                        SpendSlot::dummy(),
                    ],
                    anchor,
                    asset: usdt,
                    v_out: 25,
                    r_bridge_out: fr_from_be_bytes(&rep(0x51)),
                    npk_change: npk,
                    v_change: 15,
                    r_change: fr_from_be_bytes(&rep(0x52)),
                    bind: fr_from_be_bytes(&rep(0x53)),
                },
                h,
                z,
            )
            .expect("prove");
        }
    );

    bench!(
        "send_order",
        "send_order",
        |h: &TestCircuitHandle, z: &std::path::Path| {
            prove_send_order(
                SendOrderWitness {
                    collateral_slots: [
                        SpendSlot::real(sk, 40, fr_from_be_bytes(&rep(0x34)), path, bits),
                        SpendSlot::dummy(),
                    ],
                    fee_slots: [SpendSlot::dummy(), SpendSlot::dummy()],
                    anchor,
                    lock_asset: usdt,
                    native_asset: usdt,
                    q: 10,
                    r_locked: fr_from_be_bytes(&rep(0xB2)),
                    price: 3,
                    side_sell: false,
                    fee: 2,
                    npk_collateral_change: npk,
                    v_collateral_change: 8,
                    r_collateral_change: fr_from_be_bytes(&rep(0xB3)),
                    npk_fee_change: npk,
                    v_fee_change: 0,
                    r_fee_change: fr_from_be_bytes(&rep(0xB5)),
                    bind: fr_from_be_bytes(&rep(0xB4)),
                },
                h,
                z,
            )
            .expect("prove");
        }
    );

    bench!(
        "settle_small",
        "settle_small",
        |h: &TestCircuitHandle, z: &std::path::Path| {
            prove_settle_small(
                SettleSmallWitness {
                    q: 60,
                    r_locked: fr_from_be_bytes(&rep(0x72)),
                    collateral_price: 3,
                    execution_price: 3,
                    side_sell: true,
                    pay_asset: eth,
                    npk_ctr: npk,
                    r_note: fr_from_be_bytes(&rep(0x73)),
                    npk_refund: npk,
                    r_refund: fr_from_be_bytes(&rep(0x75)),
                    bind: fr_from_be_bytes(&rep(0x74)),
                },
                h,
                z,
            )
            .expect("prove");
        }
    );

    bench!(
        "settle_large",
        "settle_large",
        |h: &TestCircuitHandle, z: &std::path::Path| {
            prove_settle_large(
                SettleLargeWitness {
                    q: 80,
                    r_locked: fr_from_be_bytes(&rep(0x76)),
                    q_ctr: 60,
                    r_locked_ctr: fr_from_be_bytes(&rep(0x71)),
                    collateral_price: 3,
                    ctr_collateral_price: 3,
                    execution_price: 3,
                    side_sell: false,
                    r_locked_residual: fr_from_be_bytes(&rep(0x78)),
                    pay_asset: usdt,
                    npk_ctr: npk,
                    r_note: fr_from_be_bytes(&rep(0x79)),
                    npk_refund: npk,
                    r_refund: fr_from_be_bytes(&rep(0x7B)),
                    bind: fr_from_be_bytes(&rep(0x7A)),
                },
                h,
                z,
            )
            .expect("prove");
        }
    );

    bench!(
        "claim_fees",
        "claim_fees",
        |h: &TestCircuitHandle, z: &std::path::Path| {
            prove_claim_fees(
                ClaimFeesWitness {
                    asset: usdt,
                    amount: 500,
                    npk,
                    r_note: fr_from_be_bytes(&rep(0xC1)),
                    bind: fr_from_be_bytes(&rep(0xC2)),
                },
                h,
                z,
            )
            .expect("prove");
        }
    );
}
