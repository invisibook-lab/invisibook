/// Global CSS styles for the desktop application.
pub const CSS: &str = r#"
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
    --purple: #7D56F4;
    --purple-light: #9B7BF7;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

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
    padding: 10px 20px;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
}

.header-logo {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 1.5px;
    color: var(--gold);
}

.header-logo-img {
    width: 30px;
    height: 30px;
    border-radius: 6px;
    object-fit: cover;
}

.header-pair {
    font-size: 14px;
    color: var(--text-secondary);
}

/* ── Main Layout ── */
.main {
    display: flex;
    flex: 1;
    min-height: 0;
}

/* ── Order Book (left) ── */
.orderbook-panel {
    flex: 1;
    display: flex;
    flex-direction: column;
    border-right: 1px solid var(--border);
    min-width: 0;
}

.panel-title {
    padding: 10px 16px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
    background: var(--bg-card);
}

.order-table {
    flex: 1;
    overflow-y: auto;
    background: var(--bg);
}

.table-header {
    display: grid;
    grid-template-columns: 40px 90px 60px 110px 90px 1fr 70px;
    gap: 4px;
    padding: 8px 12px;
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
    grid-template-columns: 40px 90px 60px 110px 90px 1fr 70px;
    gap: 4px;
    padding: 6px 12px;
    font-size: 12px;
    cursor: pointer;
    border-bottom: 1px solid rgba(43, 49, 57, 0.5);
    transition: background 0.1s;
    align-items: center;
}

.order-row:hover { background: var(--bg-hover); }

.order-row.selected {
    background: var(--bg-hover);
    border-left: 2px solid var(--gold);
    padding-left: 10px;
}

.type-buy  { color: var(--green); font-weight: 600; }
.type-sell { color: var(--red);   font-weight: 600; }

.status-pending   { color: var(--gold); }
.status-matched   { color: var(--green); }
.status-done      { color: var(--text-third); }
.status-cancelled { color: var(--red); }
.status-frozen    { color: #3a86ff; }

.amount-cipher {
    font-size: 11px;
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

/* ── Detail Panel ── */
.detail-panel {
    grid-column: 1 / -1;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 16px;
    margin: 4px 12px;
    background: var(--bg-card);
    display: grid;
    grid-template-columns: 80px 1fr;
    gap: 6px 12px;
    font-size: 12px;
    animation: slideDown 0.12s ease-out;
}

@keyframes slideDown {
    from { opacity: 0; transform: translateY(-4px); }
    to   { opacity: 1; transform: translateY(0); }
}

.detail-label {
    color: var(--text-secondary);
    text-align: right;
}

.detail-value {
    color: var(--white);
    word-break: break-all;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 11px;
}

/* ── Trade Panel (right) ── */
.trade-panel {
    width: 320px;
    min-width: 320px;
    display: flex;
    flex-direction: column;
    background: var(--bg-card);
}

/* ── Buy / Sell Tabs ── */
.side-tabs {
    display: flex;
}

.side-tab {
    flex: 1;
    padding: 12px;
    font-size: 14px;
    font-weight: 700;
    text-align: center;
    cursor: pointer;
    border: none;
    font-family: inherit;
    transition: all 0.15s;
    color: var(--text-secondary);
    background: var(--bg);
    border-bottom: 2px solid transparent;
}

.side-tab:hover { color: var(--white); }

.side-tab.buy-active {
    color: var(--green);
    background: var(--bg-card);
    border-bottom: 2px solid var(--green);
}

.side-tab.sell-active {
    color: var(--red);
    background: var(--bg-card);
    border-bottom: 2px solid var(--red);
}

/* ── Form Body ── */
.trade-form {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: 16px;
    gap: 12px;
}

/* ── Pair Selector ── */
.pair-row {
    display: flex;
    align-items: center;
    gap: 8px;
}

.pair-select {
    flex: 1;
    background: var(--bg-input);
    color: var(--white);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 10px;
    font-family: inherit;
    font-size: 13px;
    cursor: pointer;
    outline: none;
    appearance: auto;
}

.pair-select:focus { border-color: var(--gold); }

.pair-select option { background: var(--bg-card); color: var(--white); }

.pair-slash {
    font-size: 16px;
    font-weight: 700;
    color: var(--text-third);
}

/* ── Input Group ── */
.input-group {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.input-label {
    font-size: 12px;
    color: var(--text-secondary);
}

.input-wrapper {
    display: flex;
    align-items: center;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow: hidden;
    transition: border-color 0.15s;
}

.input-wrapper:focus-within { border-color: var(--gold); }

.input-field {
    flex: 1;
    background: transparent;
    color: var(--white);
    border: none;
    padding: 10px 12px;
    font-family: inherit;
    font-size: 14px;
    outline: none;
    min-width: 0;
}

.input-field::placeholder { color: var(--text-third); }

/* Hide number input arrows */
.input-field::-webkit-inner-spin-button,
.input-field::-webkit-outer-spin-button {
    -webkit-appearance: none;
    margin: 0;
}
.input-field[type="number"] {
    -moz-appearance: textfield;
}

.input-suffix {
    padding: 0 12px;
    font-size: 13px;
    color: var(--text-secondary);
    font-weight: 600;
    white-space: nowrap;
}

/* ── Total ── */
.total-row {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
}

.total-label {
    font-size: 12px;
    color: var(--text-secondary);
}

.total-value {
    font-size: 13px;
    font-weight: 600;
    color: var(--white);
}

/* ── Balance Section ── */
.balance-section {
    display: flex;
    flex-direction: column;
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
    gap: 2px;
}

.balance-header {
    font-size: 11px;
    color: var(--text-secondary);
    margin-bottom: 2px;
}

.balance-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 2px 0;
}

.balance-token {
    font-size: 12px;
    font-weight: 600;
    color: var(--white);
}

.balance-value {
    font-size: 12px;
    font-weight: 500;
}

.balance-loading { color: var(--text-secondary); }
.balance-none    { color: var(--text-secondary); }
.balance-ok      { color: #4caf50; }

/* ── Submit Button ── */
.submit-btn {
    padding: 12px;
    border: none;
    border-radius: 4px;
    font-family: inherit;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.15s;
    letter-spacing: 0.3px;
    margin-top: auto;
}

.submit-btn.buy {
    background: var(--green);
    color: #fff;
}
.submit-btn.buy:hover { background: var(--green-hover); }

.submit-btn.sell {
    background: var(--red);
    color: #fff;
}
.submit-btn.sell:hover { background: var(--red-hover); }

.submit-btn:disabled {
    opacity: 0.35;
    cursor: not-allowed;
}

/* ── Status Toast ── */
.toast {
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    padding: 10px 24px;
    border-radius: 4px;
    font-size: 13px;
    font-weight: 600;
    z-index: 100;
    animation: fadeInUp 0.2s ease-out;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
}

.toast.success {
    background: rgba(14, 203, 129, 0.15);
    color: var(--green);
    border: 1px solid var(--green);
}

.toast.error {
    background: rgba(246, 70, 93, 0.15);
    color: var(--red);
    border: 1px solid var(--red);
}

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
.order-table::-webkit-scrollbar { width: 4px; }
.order-table::-webkit-scrollbar-track { background: transparent; }
.order-table::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
.order-table::-webkit-scrollbar-thumb:hover { background: var(--text-third); }
"#;
