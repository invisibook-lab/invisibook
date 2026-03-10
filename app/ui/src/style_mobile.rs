/// Global CSS styles for the mobile application.
pub const CSS_MOBILE: &str = r#"
:root {
    --green: #0ecb81;
    --green-hover: #0bb374;
    --red: #f6465d;
    --red-hover: #d93a50;
    --white: #eaecef;
    --text-secondary: #848e9c;
    --text-third: #5e6673;
    --gold: #f0b90b;
    --bg: #0b0e11;
    --bg-card: #1e2329;
    --bg-input: #2b3139;
    --bg-hover: #2b3139;
    --border: #2b3139;
    --tab-bar-height: 56px;
}

* { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg);
    color: var(--white);
    height: 100vh;
    overflow: hidden;
    user-select: none;
}

.app {
    display: flex;
    flex-direction: column;
    height: 100vh;
}

/* ── Header ── */
.header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
}

.header-logo {
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 1.5px;
    color: var(--gold);
}

.header-pair {
    font-size: 13px;
    color: var(--text-secondary);
}

/* ── Main content fills remaining space above tab bar ── */
.main {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
}

/* ── Order Book (full width, scrollable) ── */
.orderbook-panel {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
}

.panel-title {
    padding: 10px 14px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
    background: var(--bg-card);
    flex-shrink: 0;
}

.order-table {
    flex: 1;
    overflow-y: auto;
    background: var(--bg);
    -webkit-overflow-scrolling: touch;
}

/* 3-column grid: Side, Pair, Price — #/ID/Amount/Status hidden, shown in detail panel */
.col-id, .col-amount, .col-status, .col-index { display: none; }

.table-header {
    display: grid;
    grid-template-columns: 52px 1fr 90px;
    gap: 8px;
    padding: 8px 14px;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-third);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--bg-card);
    z-index: 1;
}

.order-row {
    display: grid;
    grid-template-columns: 52px 1fr 90px;
    gap: 8px;
    padding: 14px 14px;
    font-size: 13px;
    cursor: pointer;
    border-bottom: 1px solid rgba(43, 49, 57, 0.5);
    align-items: center;
    min-height: 50px;
}

.order-row.selected {
    background: var(--bg-hover);
    border-left: 2px solid var(--gold);
    padding-left: 8px;
}

.type-buy  { color: var(--green); font-weight: 600; }
.type-sell { color: var(--red);   font-weight: 600; }

.status-pending   { color: var(--gold); font-size: 11px; }
.status-matched   { color: var(--green); font-size: 11px; }
.status-done      { color: var(--text-third); font-size: 11px; }
.status-cancelled { color: var(--red); font-size: 11px; }

.amount-cipher {
    font-size: 10px;
    color: var(--text-third);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: 'SF Mono', 'Fira Code', monospace;
}

.amount-plain {
    font-size: 12px;
    color: var(--gold);
    font-weight: 600;
}

/* ── Detail Panel (spans full row) ── */
.detail-panel {
    grid-column: 1 / -1;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
    margin: 4px 10px;
    background: var(--bg-card);
    display: grid;
    grid-template-columns: 70px 1fr;
    gap: 8px 10px;
    font-size: 12px;
    animation: slideDown 0.12s ease-out;
}

@keyframes slideDown {
    from { opacity: 0; transform: translateY(-4px); }
    to   { opacity: 1; transform: translateY(0); }
}

.detail-label { color: var(--text-secondary); text-align: right; }

.detail-value {
    color: var(--white);
    word-break: break-all;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 11px;
}

/* ── Trade Panel (full width) ── */
.trade-panel {
    width: 100%;
    flex: 1;
    display: flex;
    flex-direction: column;
    background: var(--bg-card);
    overflow-y: auto;
    -webkit-overflow-scrolling: touch;
}

/* ── Buy / Sell Tabs ── */
.side-tabs { display: flex; }

.side-tab {
    flex: 1;
    padding: 14px;
    font-size: 15px;
    font-weight: 700;
    text-align: center;
    cursor: pointer;
    border: none;
    font-family: inherit;
    color: var(--text-secondary);
    background: var(--bg);
    border-bottom: 2px solid transparent;
    min-height: 44px;
}

.side-tab.buy-active  { color: var(--green); background: var(--bg-card); border-bottom-color: var(--green); }
.side-tab.sell-active { color: var(--red);   background: var(--bg-card); border-bottom-color: var(--red); }

/* ── Form Body ── */
.trade-form {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: 16px;
    gap: 14px;
}

/* ── Pair Selector ── */
.pair-row { display: flex; align-items: center; gap: 8px; }

.pair-select {
    flex: 1;
    background: var(--bg-input);
    color: var(--white);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 10px;
    font-family: inherit;
    font-size: 14px;
    cursor: pointer;
    outline: none;
    appearance: auto;
    min-height: 44px;
}

.pair-select:focus { border-color: var(--gold); }
.pair-select option { background: var(--bg-card); color: var(--white); }

.pair-slash { font-size: 16px; font-weight: 700; color: var(--text-third); }

/* ── Input Group ── */
.input-group { display: flex; flex-direction: column; gap: 6px; }

.input-label { font-size: 13px; color: var(--text-secondary); }

.input-wrapper {
    display: flex;
    align-items: center;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
}

.input-wrapper:focus-within { border-color: var(--gold); }

.input-field {
    flex: 1;
    background: transparent;
    color: var(--white);
    border: none;
    padding: 13px 12px;
    font-family: inherit;
    font-size: 16px;
    outline: none;
    min-width: 0;
    min-height: 44px;
}

.input-field::placeholder { color: var(--text-third); }

.input-field::-webkit-inner-spin-button,
.input-field::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
.input-field[type="number"] { -moz-appearance: textfield; }

.input-suffix {
    padding: 0 14px;
    font-size: 14px;
    color: var(--text-secondary);
    font-weight: 600;
    white-space: nowrap;
}

/* ── Total ── */
.total-row {
    display: flex;
    justify-content: space-between;
    padding: 10px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
}

.total-label { font-size: 13px; color: var(--text-secondary); }
.total-value { font-size: 14px; font-weight: 600; color: var(--white); }

/* ── Submit Button ── */
.submit-btn {
    padding: 15px;
    border: none;
    border-radius: 6px;
    font-family: inherit;
    font-size: 16px;
    font-weight: 700;
    cursor: pointer;
    letter-spacing: 0.3px;
    min-height: 52px;
    margin-top: auto;
}

.submit-btn.buy  { background: var(--green); color: #fff; }
.submit-btn.sell { background: var(--red);   color: #fff; }

.submit-btn:disabled { opacity: 0.35; cursor: not-allowed; }

/* ── Bottom Tab Bar ── */
.tab-bar {
    display: flex;
    height: var(--tab-bar-height);
    background: var(--bg-card);
    border-top: 1px solid var(--border);
    flex-shrink: 0;
}

.tab-btn {
    flex: 1;
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-family: inherit;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: color 0.15s;
    min-height: 44px;
}

.tab-btn.active { color: var(--gold); border-top: 2px solid var(--gold); }

/* ── Status Toast (raised above tab bar) ── */
.toast {
    position: fixed;
    bottom: calc(var(--tab-bar-height) + 12px);
    left: 50%;
    transform: translateX(-50%);
    padding: 10px 20px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    z-index: 100;
    animation: fadeInUp 0.2s ease-out;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    max-width: 90vw;
    text-align: center;
}

.toast.success { background: rgba(14, 203, 129, 0.15); color: var(--green); border: 1px solid var(--green); }
.toast.error   { background: rgba(246, 70, 93, 0.15);  color: var(--red);   border: 1px solid var(--red); }

@keyframes fadeInUp {
    from { opacity: 0; transform: translateX(-50%) translateY(8px); }
    to   { opacity: 1; transform: translateX(-50%) translateY(0); }
}

/* ── Empty State ── */
.empty-state {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text-third);
    font-size: 13px;
}

/* ── Scrollbar ── */
.order-table::-webkit-scrollbar { width: 3px; }
.order-table::-webkit-scrollbar-track { background: transparent; }
.order-table::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
"#;
