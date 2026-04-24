use crate::model::App;
use invisibook_lib::cash_store::CashRecord;
use invisibook_lib::command as lib_cmd;
use invisibook_lib::orderbook;
use invisibook_lib::types::*;


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
        let amount: u64 = result.plain_amount.as_ref()
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
            orderbook::CashSelection::WithChange { cash_ids, change_amount } => {
                let (change_cipher, _, change_random) =
                    orderbook::encrypt_amount_with_info(&change_amount.to_string());
                let change_cash_id = orderbook::compute_cash_id(&app.my_address, &input_token, &change_cipher);
                let change = CashChange {
                    cash_id: change_cash_id.clone(),
                    amount: change_cipher,
                };
                (cash_ids, Some((change, change_cash_id, change_amount, change_random)))
            }
            orderbook::CashSelection::Insufficient => {
                app.message = Some(format!("✗ Insufficient {} balance (need {})", input_token, total));
                app.is_error = true;
                return;
            }
        };

        // Set the real input_cash_ids and recompute order ID
        order.input_cash_ids = input_cash_ids.clone();
        order.id = orderbook::compute_order_id(&input_cash_ids);
        order.pubkey = app.my_address.clone();

        let change_ref = cash_change.as_ref().map(|(c, _, _, _)| c);
        let client = client.clone();
        match app.runtime.block_on(client.send_order(&order, change_ref)) {
            Ok(()) => {
                // Update CashStore on split
                if let Some((_, change_cash_id, change_amount, change_random)) = cash_change {
                    for rec in app.cash_store.records_mut().iter_mut() {
                        if input_cash_ids.contains(&rec.cash_id) {
                            rec.status = CASH_SPENT;
                        }
                    }
                    app.cash_store.records_mut().push(CashRecord {
                        cash_id: change_cash_id,
                        token: input_token,
                        amount: change_amount,
                        random: change_random,
                        status: CASH_ACTIVE,
                    });
                    let _ = app.cash_store.flush();
                }

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

// ────────────────────── Context Suggestions ──────────────────────
// Re-export from lib.

pub fn context_suggestions(value: &str) -> Vec<String> {
    lib_cmd::context_suggestions(value)
}
