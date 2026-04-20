use crate::model::App;
use invisibook_lib::command as lib_cmd;
use invisibook_lib::orderbook;

// ────────────────────── Command Handling ──────────────────────
// Thin adapter: calls lib::parse_command and applies the result to App state.
// If a chain client is available, sends the order to the chain.

pub fn handle_command(app: &mut App, input: &str) {
    let result = lib_cmd::parse_command(input);

    if let Some(order) = result.order {
        // Try sending to chain first
        if let Some(ref client) = app.chain_client {
            let client = client.clone();
            let send_result = app.runtime.block_on(client.send_order(&order));
            match send_result {
                Ok(()) => {
                    let order_id = order.id.clone();
                    app.orders.push(order);
                    if let Some(plain) = result.plain_amount {
                        app.own_order_ids.insert(order_id, plain);
                    }
                    orderbook::sort_orders(&mut app.orders);
                    app.expanded = None;
                    app.message = Some(result.message);
                    app.is_error = false;
                }
                Err(e) => {
                    app.message = Some(format!("✗ Send order failed: {}", e));
                    app.is_error = true;
                }
            }
        } else {
            // No chain client — local only
            let order_id = order.id.clone();
            app.orders.push(order);
            if let Some(plain) = result.plain_amount {
                app.own_order_ids.insert(order_id, plain);
            }
            orderbook::sort_orders(&mut app.orders);
            app.expanded = None;
            app.message = Some(result.message);
            app.is_error = result.is_error;
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
