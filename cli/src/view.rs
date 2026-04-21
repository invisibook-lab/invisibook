use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::command;
use crate::model::App;
use invisibook_lib::orderbook;
use invisibook_lib::types::*;

// ────────────────────── Colors (matching Go lipgloss styles) ──────────────────────

const PURPLE: Color = Color::Rgb(125, 86, 244); // #7D56F4
const WHITE: Color = Color::Rgb(250, 250, 250); // #FAFAFA
const GOLD: Color = Color::Rgb(255, 215, 0); // #FFD700
const GREEN: Color = Color::Rgb(4, 181, 117); // #04B575
const RED: Color = Color::Rgb(255, 107, 107); // #FF6B6B
const GRAY: Color = Color::Rgb(102, 102, 102); // #666666
const DIM_GRAY: Color = Color::Rgb(136, 136, 136); // #888888

// ────────────────────── Main Render ──────────────────────

pub fn render_ui(f: &mut Frame, app: &App) {
    let area = f.area();
    let mut lines: Vec<Line> = Vec::new();
    let input_line_y: usize;

    // ── Title ──
    lines.push(Line::from(vec![
        Span::styled(
            "  INVISIBOOK Order Book  ",
            Style::default().fg(WHITE).bg(PURPLE).bold(),
        ),
        Span::raw("  "),
        Span::styled(
            if app.my_address.is_empty() { "not connected".to_string() } else { format!("addr: {}", &app.my_address) },
            Style::default().fg(DIM_GRAY),
        ),
    ]));

    // ── Balances by TokenID ──
    if !app.balances.is_empty() {
        let mut sorted_tokens: Vec<(&String, &usize)> = app.balances.iter().collect();
        sorted_tokens.sort_by_key(|(t, _)| t.as_str());
        let mut balance_spans: Vec<Span> = vec![
            Span::styled("  Balances  ", Style::default().fg(GOLD).bold()),
        ];
        for (i, (token, active)) in sorted_tokens.iter().enumerate() {
            if i > 0 {
                balance_spans.push(Span::styled(" │ ", Style::default().fg(DIM_GRAY)));
            }
            let count_style = if **active > 0 {
                Style::default().fg(GREEN)
            } else {
                Style::default().fg(DIM_GRAY)
            };
            balance_spans.push(Span::styled(format!("{}: ", token), Style::default().fg(WHITE)));
            balance_spans.push(Span::styled(format!("{} active", active), count_style));
        }
        lines.push(Line::from(balance_spans));
    }
    lines.push(Line::from(""));

    if app.orders.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (No orders)",
            Style::default().fg(DIM_GRAY),
        )));
    } else {
        // Header
        let header = format!(
            "  {:<3}  {:<10}  {:<6}  {:<12}  {:<14}  {}",
            "#", "OrderID", "Type", "Pair", "Price", "Amount"
        );
        lines.push(Line::from(Span::styled(
            header,
            Style::default().fg(PURPLE).bold(),
        )));
        lines.push(Line::from(Span::styled(
            format!("  {}", "─".repeat(76)),
            Style::default().fg(DIM_GRAY),
        )));

        // Rows
        for (i, order) in app.orders.iter().enumerate() {
            let selected = i == app.cursor;

            // cursor indicator
            let prefix = if selected {
                Span::styled(" ▶ ", Style::default().fg(GOLD).bold())
            } else {
                Span::raw("   ")
            };

            // trade type
            let type_span = match order.trade_type {
                TradeType::Buy => Span::styled("BUY ", Style::default().fg(GREEN).bold()),
                TradeType::Sell => Span::styled("SELL", Style::default().fg(RED).bold()),
            };

            // price
            let price_str = match order.price {
                Some(p) => p.to_string(),
                None => "-".into(),
            };

            // amount
            let amount = app.display_amount(order);

            let row_style = if selected {
                Style::default().bold()
            } else {
                Style::default()
            };

            let line = Line::from(vec![
                prefix,
                Span::styled(format!("{:<3}  {:<10}  ", i + 1, orderbook::short_id(&order.id)), row_style),
                type_span,
                Span::styled(
                    format!("  {:<12}  {:<14}  {}", order.subject, price_str, amount),
                    row_style,
                ),
            ]);
            lines.push(line);

            // expanded detail
            if app.expanded == Some(i) {
                let detail_lines = render_detail(app, order);
                lines.extend(detail_lines);
            }
        }
    }

    // ── Status message ──
    if let Some(ref msg) = app.message {
        lines.push(Line::from(""));
        let style = if app.is_error {
            Style::default().fg(RED).bold()
        } else {
            Style::default().fg(GREEN).bold()
        };
        lines.push(Line::from(Span::styled(format!("  {}", msg), style)));
    }

    // ── Input area ──
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  ─── Command {}", "─".repeat(52)),
        Style::default().fg(DIM_GRAY),
    )));

    // Record the input line index for cursor positioning
    input_line_y = lines.len();

    // Build input line with suggestion ghost text
    let input_prefix = Span::styled("  ❯ ", Style::default().fg(PURPLE).bold());
    let suggestions = command::context_suggestions(&app.input.value);
    let matching = suggestions
        .iter()
        .find(|s| s.starts_with(&app.input.value) && *s != &app.input.value);

    if app.input.value.is_empty() {
        // Show placeholder
        lines.push(Line::from(vec![
            input_prefix,
            Span::styled(
                app.input.placeholder.clone(),
                Style::default().fg(DIM_GRAY),
            ),
        ]));
    } else if let Some(suggestion) = matching {
        let remaining = &suggestion[app.input.value.len()..];
        lines.push(Line::from(vec![
            input_prefix,
            Span::raw(app.input.value.clone()),
            Span::styled(remaining.to_string(), Style::default().fg(DIM_GRAY)),
        ]));
    } else {
        lines.push(Line::from(vec![
            input_prefix,
            Span::raw(app.input.value.clone()),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Up/Down: navigate | Enter: expand / run command | Tab: autocomplete | Esc: quit",
        Style::default().fg(GRAY).italic(),
    )));

    let paragraph = Paragraph::new(Text::from(lines));
    f.render_widget(paragraph, area);

    // Set cursor position at the input line
    // "  ❯ " = 4 display columns, then the cursor position within the input
    let cursor_x = area.x + 4 + app.input.cursor as u16;
    let cursor_y = area.y + input_line_y as u16;
    f.set_cursor_position((cursor_x, cursor_y));
}

// ────────────────────── Detail Panel ──────────────────────

fn render_detail(app: &App, order: &Order) -> Vec<Line<'static>> {
    let margin = "    ";
    let inner_width: usize = 42;

    let mut result: Vec<Line<'static>> = Vec::new();

    // Top border  ╭─...─╮
    result.push(Line::from(Span::styled(
        format!("{}╭─{}─╮", margin, "─".repeat(inner_width)),
        Style::default().fg(PURPLE),
    )));

    // Helper: create a bordered content line
    let bordered = |label: &str, value: String| -> Line<'static> {
        let content = format!("{:<12} {}", label, value);
        let padding = inner_width.saturating_sub(content.chars().count());
        Line::from(vec![
            Span::styled(format!("{}│ ", margin), Style::default().fg(PURPLE)),
            Span::raw(format!("{}{}", content, " ".repeat(padding))),
            Span::styled(" │".to_string(), Style::default().fg(PURPLE)),
        ])
    };

    // Order ID
    result.push(bordered("Order ID:", orderbook::short_id(&order.id).to_string()));

    // Type (with color)
    let type_label = "Type:       ";
    let (type_val, type_color) = match order.trade_type {
        TradeType::Buy => ("BUY", GREEN),
        TradeType::Sell => ("SELL", RED),
    };
    let type_padding =
        inner_width.saturating_sub(type_label.chars().count() + type_val.chars().count());
    result.push(Line::from(vec![
        Span::styled(format!("{}│ ", margin), Style::default().fg(PURPLE)),
        Span::raw(type_label.to_string()),
        Span::styled(
            type_val.to_string(),
            Style::default().fg(type_color).bold(),
        ),
        Span::raw(" ".repeat(type_padding)),
        Span::styled(" │".to_string(), Style::default().fg(PURPLE)),
    ]));

    // Pair
    result.push(bordered("Pair:", order.subject.to_string()));

    // Price
    let price_str = match order.price {
        Some(p) => p.to_string(),
        None => "-".into(),
    };
    result.push(bordered("Price:", price_str));

    // Amount
    result.push(bordered("Amount:", app.display_amount_full(order)));

    // Status
    result.push(bordered("Status:", order.status.to_string()));

    // Bottom border  ╰─...─╯
    result.push(Line::from(Span::styled(
        format!("{}╰─{}─╯", margin, "─".repeat(inner_width)),
        Style::default().fg(PURPLE),
    )));

    result
}
