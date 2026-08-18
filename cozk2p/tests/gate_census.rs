//! Gate census of the two PLONK relations: build the REAL circuits with a
//! step tracer and print each step's measured gate delta. The numbers in
//! docs/settlement_protocol.md §4 come from this output — run with
//! `cargo test --test gate_census -- --nocapture`.

use cozk2p::{
    compute_public,
    relation::{
        PublicWires, SideWires, build_settle_relation_traced, side_private_values,
        side_wires_from_vars,
    },
    sample_trade,
};
use mpc_relation::{PlonkCircuit, Variable, traits::Circuit};

/// Collect (label, running-gate-count) pairs and print the delta table.
fn print_deltas(name: &str, marks: &[(String, usize)], finalized: usize) {
    eprintln!("\n── {name} — measured TurboPlonk gates per step ──");
    let mut prev = marks[0].1;
    eprintln!("{:<52} {:>8}", "(allocation baseline)", prev);
    for (label, at) in &marks[1..] {
        eprintln!("{:<52} {:>8}", label, at - prev);
        prev = *at;
    }
    eprintln!("{:<52} {:>8}", "TOTAL before padding", prev);
    eprintln!(
        "{:<52} {:>8}",
        "TOTAL after finalize (padded domain)", finalized
    );
}

/// Allocate a list of plaintext values as private variables.
fn alloc(cs: &mut PlonkCircuit<ark_bn254::Fr>, vals: Vec<ark_bn254::Fr>) -> Vec<Variable> {
    vals.into_iter()
        .map(|v| cs.create_variable(v).unwrap())
        .collect()
}

/// π_cmp: the compare-only relation (5 publics, locked-only model).
#[test]
fn census_compare_relation() {
    let (a, b, price, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price, a_is_seller).unwrap();

    let mut cs = PlonkCircuit::<ark_bn254::Fr>::new_turbo_plonk();
    let pub_vars: Vec<Variable> = public
        .to_vec()
        .into_iter()
        .map(|v| cs.create_public_variable(v).unwrap())
        .collect();
    let pw = PublicWires {
        cmp: pub_vars[0],
        locked_a: pub_vars[1],
        locked_b: pub_vars[2],
        price: pub_vars[3],
        a_is_seller: pub_vars[4],
    };
    let a_vars = alloc(&mut cs, side_private_values(&a));
    let b_vars = alloc(&mut cs, side_private_values(&b));
    let aw: SideWires = side_wires_from_vars(&a_vars);
    let bw: SideWires = side_wires_from_vars(&b_vars);

    let mut marks: Vec<(String, usize)> = Vec::new();
    build_settle_relation_traced(&mut cs, &pw, &aw, &bw, &mut |label, gates| {
        marks.push((label.to_string(), gates));
    })
    .unwrap();
    cs.check_circuit_satisfiability(&public.to_vec()).unwrap();
    cs.finalize_for_arithmetization().unwrap();
    print_deltas("pi_cmp (compare relation)", &marks, cs.num_gates());
}
