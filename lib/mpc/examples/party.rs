//! Demo binary that runs the full 2PC LT+Poseidon circuit in a single process.
//!
//! Because we use ark-mpc's in-process duplex transport instead of a real
//! network, both parties run as tokio tasks sharing one runtime. The user
//! supplies the two amounts and a strategy; the binary computes the public
//! Poseidon hashes of each amount (so the caller does not have to paste
//! them as hex), runs the MPC circuit, and prints the outcome.

use std::time::Instant;

use clap::{Parser, ValueEnum};
use light_poseidon::{Poseidon, PoseidonHasher};
use mpc::{CompareStrategy, Fr, run_inprocess};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum StrategyArg {
    BitDirect,
    SignBit,
    PrefixOr,
}

impl From<StrategyArg> for CompareStrategy {
    fn from(s: StrategyArg) -> Self {
        match s {
            StrategyArg::BitDirect => CompareStrategy::BitDirect,
            StrategyArg::SignBit => CompareStrategy::SignBit,
            StrategyArg::PrefixOr => CompareStrategy::PrefixOr,
        }
    }
}

#[derive(Parser, Debug)]
#[command(about = "Two-party private less-than with Poseidon commitment check")]
struct Args {
    /// Party 0's private amount.
    #[arg(long)]
    amount_p0: u64,
    /// Party 1's private amount.
    #[arg(long)]
    amount_p1: u64,
    /// Which SPDZ comparison gadget to use.
    #[arg(long, value_enum, default_value_t = StrategyArg::SignBit)]
    strategy: StrategyArg,
}

/// Plaintext Poseidon oracle, compatible with the in-circuit hasher.
fn poseidon_single(x: u64) -> Fr {
    let mut hasher = Poseidon::<Fr>::new_circom(1).expect("circom(1) params");
    hasher.hash(&[Fr::from(x)]).expect("poseidon hash")
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let hash_a = poseidon_single(args.amount_p0);
    let hash_b = poseidon_single(args.amount_p1);

    let start = Instant::now();
    let lt = run_inprocess(
        args.amount_p0,
        args.amount_p1,
        hash_a,
        hash_b,
        CompareStrategy::from(args.strategy),
    )
    .await
    .expect("MPC circuit failed");
    let elapsed = start.elapsed();

    println!(
        "strategy={:?}  a={}  b={}  a<b = {lt}  (took {elapsed:?})",
        args.strategy, args.amount_p0, args.amount_p1
    );
}
