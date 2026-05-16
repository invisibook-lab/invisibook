use crate::model::App;
use invisibook_lib::{cash_store::CashRecord, command as lib_cmd, orderbook, types::*};
use zk::{
    setup::dev_setup_snarkjs,
    test_circuit::TestCircuitHandle,
    wallet::{SplitWitness, prove_split},
};

// ────────────────────── Command Handling ──────────────────────
// Thin adapter: calls lib::parse_command and applies the result to App state.
// If a chain client is available, sends the order to the chain.

pub fn handle_command(app: &mut App, input: &str) {
    let result = lib_cmd::parse_command(input);

    if let Some(mut order) = result.order {
        let Some(ref client) = app.chain_client else {
            app.message = Some("✗ Not connected to chain".into());
            app.is_error = true;
            return;
        };

        // Determine input token and total
        let input_token = if order.trade_type == TradeType::Buy {
            order.subject.token2.clone()
        } else {
            order.subject.token1.clone()
        };

        let price = order.price.unwrap_or(0);
        let amount: u64 = result
            .plain_amount
            .as_ref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let total: u64 = if order.trade_type == TradeType::Buy {
            price * amount
        } else {
            amount
        };

        // Smart cash selection
        let selection = orderbook::select_cash(app.cash_store.records(), &input_token, total);
        let (input_cash_ids, cash_change) = match selection {
            orderbook::CashSelection::Exact(ids) => (ids, None),
            orderbook::CashSelection::WithChange {
                cash_ids,
                change_amount,
            } => {
                let (change_cipher, _, change_random) =
                    orderbook::encrypt_amount_with_info(&change_amount.to_string());
                let change_cash_id =
                    orderbook::compute_cash_id(&app.my_address, &input_token, &change_cipher);
                let change = CashChange {
                    cash_id: change_cash_id.clone(),
                    amount: change_cipher,
                };
                (
                    cash_ids,
                    Some((change, change_cash_id, change_amount, change_random)),
                )
            }
            orderbook::CashSelection::Insufficient => {
                app.message = Some(format!(
                    "✗ Insufficient {} balance (need {})",
                    input_token, total
                ));
                app.is_error = true;
                return;
            }
        };

        // The split circuit caps inputs at 2; refuse early so the user sees a
        // clear error instead of a cryptic prover failure later.
        if input_cash_ids.len() > 2 {
            app.message = Some(format!(
                "✗ Selector picked {} inputs but split circuit caps at 2 — consolidate first",
                input_cash_ids.len()
            ));
            app.is_error = true;
            return;
        }

        // Set the real input_cash_ids and recompute order ID
        order.input_cash_ids = input_cash_ids.clone();
        order.id = orderbook::compute_order_id(&input_cash_ids);
        order.pubkey = app.my_address.clone();

        // In split mode we must produce a conservation proof. Pull the input
        // (amount, random) pairs from CashStore, then compute the locked
        // commitment opening from result.locked_random + plaintext amount.
        let split_proof = if let Some((_, _, change_amount, ref change_random_hex)) = cash_change {
            let proof = match build_split_proof(
                app,
                &input_cash_ids,
                amount,
                result.locked_random.as_deref().unwrap_or(""),
                change_amount,
                change_random_hex,
            ) {
                Ok(p) => p,
                Err(e) => {
                    app.message = Some(format!("✗ split proof failed: {e}"));
                    app.is_error = true;
                    return;
                }
            };
            Some(proof)
        } else {
            None
        };

        let change_ref = cash_change.as_ref().map(|(c, _, _, _)| c);
        let client = client.clone();
        match app
            .runtime
            .block_on(client.send_order(&order, change_ref, split_proof))
        {
            Ok(()) => {
                // CashStore updates on every successful send_order:
                //   * inputs → SPENT (split) or LOCKED (non-split)
                //   * change cash → ACTIVE  (split only)
                //   * locked cash → LOCKED  (split only — the pre-split lock just
                //     mutates the input record in place above)
                let locked_random = result.locked_random.clone();
                if let Some((_, change_cash_id, change_amount, change_random)) = cash_change {
                    // Split: spend originals, mint two new records (locked + change)
                    for rec in app.cash_store.records_mut().iter_mut() {
                        if input_cash_ids.contains(&rec.cash_id) {
                            rec.status = CASH_SPENT;
                        }
                    }
                    app.cash_store.records_mut().push(CashRecord {
                        cash_id: change_cash_id,
                        token: input_token.clone(),
                        amount: change_amount,
                        random: change_random,
                        status: CASH_ACTIVE,
                    });
                    let locked_commitment = order.amount.clone();
                    let locked_cash_id = orderbook::compute_cash_id(
                        &app.my_address,
                        &input_token,
                        &locked_commitment,
                    );
                    app.cash_store.records_mut().push(CashRecord {
                        cash_id: locked_cash_id,
                        token: input_token,
                        amount,
                        random: locked_random.unwrap_or_default(),
                        status: CASH_LOCKED,
                    });
                } else {
                    // Non-split lock: the input cash itself transitions Active → Locked.
                    // Amount/random stay unchanged so SettleOrder can later open it.
                    for rec in app.cash_store.records_mut().iter_mut() {
                        if input_cash_ids.contains(&rec.cash_id) {
                            rec.status = CASH_LOCKED;
                        }
                    }
                }
                let _ = app.cash_store.flush();

                if let Some(plain) = result.plain_amount {
                    app.own_order_ids.insert(order.id.clone(), plain);
                }
                app.expanded = None;
                app.message = Some("⏳ Submitting to chain...".to_string());
                app.is_error = false;
            }
            Err(e) => {
                app.message = Some(format!("✗ Send order failed: {e}"));
                app.is_error = true;
            }
        }
    } else {
        app.message = Some(result.message);
        app.is_error = result.is_error;
    }
}

/// Compile + setup the split circuit (cached after first call) and prove the
/// conservation constraint for this SendOrder. Returns the snarkjs `proof.json`
/// as a string ready to embed in the chain request.
///
/// `input_cash_ids` must reference Active records present in `app.cash_store`;
/// `locked_random_hex` is the 32-byte hex from `lib_cmd::CommandResult` and
/// must not be empty (parse_command guarantees this on success).
fn build_split_proof(
    app: &App,
    input_cash_ids: &[String],
    locked_amount: u64,
    locked_random_hex: &str,
    change_amount: u64,
    change_random_hex: &str,
) -> Result<String, String> {
    let setup = dev_setup_snarkjs("split").map_err(|e| format!("snarkjs setup: {e}"))?;
    let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir)
        .map_err(|e| format!("compile circuit: {e}"))?;

    let mut inputs = Vec::with_capacity(input_cash_ids.len());
    for id in input_cash_ids {
        let rec = app
            .cash_store
            .records()
            .iter()
            .find(|r| &r.cash_id == id)
            .ok_or_else(|| format!("input cash {id} missing from local CashStore"))?;
        let raw = hex::decode(&rec.random).map_err(|e| format!("bad random hex: {e}"))?;
        if raw.len() != 32 {
            return Err(format!(
                "cash {id} random must be 32 bytes, got {}",
                raw.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        inputs.push((rec.amount, arr));
    }

    let locked_random = parse_random_hex(locked_random_hex)?;
    let change_random = parse_random_hex(change_random_hex)?;

    let sp = prove_split(
        SplitWitness {
            inputs,
            locked_amount,
            locked_random,
            change_amount,
            change_random,
        },
        &handle,
        &setup.zkey,
    )
    .map_err(|e| format!("prove_split: {e}"))?;
    serde_json::to_string(&sp.proof_json).map_err(|e| format!("serialize proof: {e}"))
}

fn parse_random_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid random hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("random must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ────────────────────── Context Suggestions ──────────────────────
// Re-export from lib.

pub fn context_suggestions(value: &str) -> Vec<String> {
    lib_cmd::context_suggestions(value)
}
