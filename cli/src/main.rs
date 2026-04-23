mod command;
mod model;
mod view;

use std::io;
use std::sync::Arc;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;

use invisibook_lib::chain::{ChainClient, OrderEvent};
use invisibook_lib::config::ClientConfig;
use invisibook_lib::types::CASH_ACTIVE;
use yu_sdk::KeyPair;

use model::App;

fn main() -> io::Result<()> {
    // ── Chain client + initial orders ──
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    let cfg = ClientConfig::load_with_args();
    let (client, initial_orders, my_address) = match cfg.seed() {
        Ok(seed) => {
            let kp = KeyPair::from_ed25519_bytes(&seed);
            let pubkey = hex::encode(kp.pubkey_bytes());
            let c = Arc::new(ChainClient::new(
                &cfg.chain.http_url,
                &cfg.chain.ws_url,
                seed,
                cfg.chain.chain_id,
            ));
            let orders = rt.block_on(async {
                c.query_orders(None, None, None, None, None, Some(100), Some(0))
                    .await
                    .ok()
            });
            (Some(c), orders, pubkey)
        }
        Err(e) => {
            eprintln!("Failed to parse keypair: {}", e);
            (None, None, String::new())
        }
    };

    // ── Fetch initial balances per token ──
    let initial_balances: std::collections::HashMap<String, usize> = if let Some(ref c) = client {
        let mut bals = std::collections::HashMap::new();
        for token in ["ETH", "BTC", "SOL", "USDT", "USDC", "DAI"] {
            if let Ok(acc) = rt.block_on(c.get_account(&my_address, token)) {
                let active = acc.cash.iter().filter(|c| c.status == CASH_ACTIVE).count();
                bals.insert(token.to_string(), active);
            }
        }
        bals
    } else {
        std::collections::HashMap::new()
    };

    // ── Background WS subscription ──
    let (order_tx, order_rx) = std::sync::mpsc::channel::<OrderEvent>();
    if let Some(ref c) = client {
        let c_clone = c.clone();
        rt.spawn(async move {
            match c_clone.subscribe_order_events().await {
                Ok((mut rx, _handle)) => {
                    while let Some(event) = rx.recv().await {
                        let _ = order_tx.send(event);
                    }
                }
                Err(e) => eprintln!("WS subscription failed: {e}"),
            }
        });
    }

    // ── Setup terminal ──
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // ── Run app ──
    let mut app = App::new_with(initial_orders, client, rt, Some(order_rx), my_address, initial_balances);
    let result = run_app(&mut terminal, &mut app);

    // ── Restore terminal ──
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = result {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|f| view::render_ui(f, app))?;

        // Drain any confirmed orders from the WS subscription task.
        app.process_chain_events();

        // Poll for key events with a short timeout so chain events are visible
        // promptly even without user input.
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Esc => return Ok(()),
                        KeyCode::Char('c')
                            if key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            return Ok(())
                        }
                        KeyCode::Up => app.move_cursor_up(),
                        KeyCode::Down => app.move_cursor_down(),
                        KeyCode::Enter => app.handle_enter(),
                        KeyCode::Backspace => app.input_backspace(),
                        KeyCode::Tab => app.accept_suggestion(),
                        KeyCode::Char(c) => app.input_char(c),
                        _ => {}
                    }
                }
            }
        }
    }
}
