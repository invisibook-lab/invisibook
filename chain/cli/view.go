package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/invisibook-lab/invisibook/core"
)

// ────────────────────── View ──────────────────────

func (m model) View() string {
	var b strings.Builder

	// ── Title ──
	b.WriteString(titleStyle.Render("  📖  INVISIBOOK 订单薄  "))
	b.WriteString("\n\n")

	if len(m.orders) == 0 {
		b.WriteString(dimStyle.Render("  (暂无订单)\n"))
	} else {
		// Header
		header := fmt.Sprintf("  %-3s  %-6s  %-12s  %-14s  %s",
			"#", "类型", "交易对", "报价", "数量(密文)")
		b.WriteString(headerStyle.Render(header))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  " + strings.Repeat("─", 66)))
		b.WriteString("\n")

		// Rows
		for i, order := range m.orders {
			selected := i == m.cursor

			// cursor indicator
			prefix := "   "
			if selected {
				prefix = cursorStyle.Render(" ▶ ")
			}

			// trade type
			typeStr := buyStyle.Render("BUY ")
			if order.Type == core.Sell {
				typeStr = sellStyle.Render("SELL")
			}

			// pair
			pair := order.Subject.String()

			// price
			priceStr := "-"
			if order.Price != nil {
				priceStr = order.Price.String()
			}

			// amount (cipher)
			amount := string(order.Amount)
			if len(amount) > 22 {
				amount = amount[:22] + "…"
			}

			line := fmt.Sprintf("%s%-3d  %s  %-12s  %-14s  %s",
				prefix, i+1, typeStr, pair, priceStr, amount)

			if selected {
				b.WriteString(lipgloss.NewStyle().Bold(true).Render(line))
			} else {
				b.WriteString(line)
			}
			b.WriteString("\n")

			// expanded detail
			if i == m.expanded {
				b.WriteString(m.renderDetail(order))
				b.WriteString("\n")
			}
		}
	}

	// ── Status message ──
	if m.message != "" {
		b.WriteString("\n")
		if m.isError {
			b.WriteString(errStyle.Render("  " + m.message))
		} else {
			b.WriteString(msgStyle.Render("  " + m.message))
		}
		b.WriteString("\n")
	}

	// ── Input area ──
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  ─── 输入命令 " + strings.Repeat("─", 51)))
	b.WriteString("\n  ")
	b.WriteString(m.input.View())
	b.WriteString("\n\n")
	b.WriteString(hintStyle.Render("  ↑↓ 移动光标 │ Enter 展开详情 / 执行命令 │ Esc 退出"))
	b.WriteString("\n")

	return b.String()
}

// ────────────────────── Detail Panel ──────────────────────

func (m model) renderDetail(order core.Order) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("订单 ID:     %s\n", order.ID))

	typeStr := buyStyle.Render("买入 (BUY)")
	if order.Type == core.Sell {
		typeStr = sellStyle.Render("卖出 (SELL)")
	}
	b.WriteString(fmt.Sprintf("类型:        %s\n", typeStr))
	b.WriteString(fmt.Sprintf("交易对:      %s\n", order.Subject.String()))

	priceStr := "-"
	if order.Price != nil {
		priceStr = order.Price.String()
	}
	b.WriteString(fmt.Sprintf("报价:        %s\n", priceStr))
	b.WriteString(fmt.Sprintf("数量(密文):  %s\n", order.Amount))

	var statusStr string
	switch order.Status {
	case core.Pending:
		statusStr = "⏳ 待处理"
	case core.Matched:
		statusStr = "🔗 已匹配"
	case core.Done:
		statusStr = "✅ 已完成"
	case core.Cancelled:
		statusStr = "❌ 已取消"
	default:
		statusStr = "未知"
	}
	b.WriteString(fmt.Sprintf("状态:        %s", statusStr))

	if len(order.Targets) > 0 {
		targets := make([]string, len(order.Targets))
		for i, t := range order.Targets {
			targets[i] = string(t)
		}
		b.WriteString(fmt.Sprintf("\n匹配目标:    [%s]", strings.Join(targets, ", ")))
	}

	return detailBorderStyle.Render(b.String())
}
