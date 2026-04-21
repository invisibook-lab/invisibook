use crate::model::App;
use invisibook_lib::command as lib_cmd;


// ────────────────────── Command Handling ──────────────────────
// Thin adapter: calls lib::parse_command and applies the result to App state.
// If a chain client is available, sends the order to the chain.

pub fn handle_command(app: &mut App, input: &str) {
    let result = lib_cmd::parse_command(input);

    if let Some(order) = result.order {
        let Some(ref client) = app.chain_client else {
            app.message = Some("✗ Not connected to chain".into());
            app.is_error = true;
            return;
        };
        let client = client.clone();
        match app.runtime.block_on(client.send_order(&order)) {
            Ok(()) => {
                // Order accepted by chain. WS subscription will confirm it.
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
