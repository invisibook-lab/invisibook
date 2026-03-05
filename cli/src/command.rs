use crate::model::App;
use invisibook_lib::command as lib_cmd;
use invisibook_lib::orderbook;

// ────────────────────── Command Handling ──────────────────────
// Thin adapter: calls lib::parse_command and applies the result to App state.

pub fn handle_command(app: &mut App, input: &str) {
    let result = lib_cmd::parse_command(input);

    if let Some(order) = result.order {
        let order_id = order.id.clone();
        app.orders.push(order);
        if let Some(plain) = result.plain_amount {
            app.own_order_ids.insert(order_id, plain);
        }
        orderbook::sort_orders(&mut app.orders);
        app.expanded = None;
    }

    app.message = Some(result.message);
    app.is_error = result.is_error;
}

// ────────────────────── Context Suggestions ──────────────────────
// Re-export from lib.

pub fn context_suggestions(value: &str) -> Vec<String> {
    lib_cmd::context_suggestions(value)
}
