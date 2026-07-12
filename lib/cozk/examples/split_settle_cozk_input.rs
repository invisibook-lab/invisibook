// Offline input splitter for the pre-shared party flow (mirrors co-circom's
// `split-input` CLI step): turns each trader's private side JSON plus the
// shared public JSON into three per-node REP3 share files.
//
// Run with:
//   cargo run -p cozk --example split_settle_cozk_input -- \
//       <a_side.json> <b_side.json> <public.json> <out_dir>
//
// Writes <out_dir>/share_{a,b}.{0,1,2}.json; give node i its share_a.i.json
// and share_b.i.json via settle_cozk_party --share-a-json/--share-b-json.

use std::{env, fs, path::PathBuf};

use cozk::{default_circuit_path, default_link_dir, load_artifacts, split_trader_input};
use serde_json::Value;
use zk::setup::dev_setup_snarkjs;

fn main() {
    let mut args = env::args().skip(1).map(PathBuf::from);
    let (a_path, b_path, public_path, out_dir) = (
        args.next()
            .expect("usage: <a_side> <b_side> <public> <out_dir>"),
        args.next().expect("missing b_side.json"),
        args.next().expect("missing public.json"),
        args.next().expect("missing out_dir"),
    );

    let setup = dev_setup_snarkjs("settle_cozk").expect("snarkjs setup");
    let artifacts = load_artifacts(
        &default_circuit_path(),
        &default_link_dir(),
        &setup.zkey,
        &setup.vk_json,
    )
    .expect("loading artifacts");

    let read = |p: &PathBuf| -> Value {
        serde_json::from_str(&fs::read_to_string(p).expect("reading input file"))
            .expect("parsing input file")
    };
    let public = read(&public_path);
    fs::create_dir_all(&out_dir).expect("creating out dir");
    for (tag, path) in [("a", &a_path), ("b", &b_path)] {
        let side = read(path);
        let shares = split_trader_input(&side, &public, &artifacts.public_input_names)
            .expect("splitting input");
        for (i, share) in shares.iter().enumerate() {
            let out = out_dir.join(format!("share_{tag}.{i}.json"));
            fs::write(
                &out,
                serde_json::to_string(share).expect("serializing share"),
            )
            .expect("writing share file");
            println!("wrote {}", out.display());
        }
    }
}
