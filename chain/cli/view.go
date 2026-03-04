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
	b.WriteString(titleStyle.Render("  INVISIBOOK Order Book  "))
	b.WriteString("\n\n")

	if len(m.orders) == 0 {
		b.WriteString(dimStyle.Render("  (No orders)\n"))
	} else {
		// Header
		header := fmt.Sprintf("  %-3s  %-6s  %-12s  %-14s  %s",
			"#", "Type", "Pair", "Price", "Amount")
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

			// amount: show plain text for own orders, cipher for others
			amount := m.displayAmount(order)

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
	b.WriteString(dimStyle.Render("  ─── Command " + strings.Repeat("─", 52)))
	b.WriteString("\n  ")
	b.WriteString(m.input.View())
	b.WriteString("\n\n")
	b.WriteString(hintStyle.Render("  Up/Down: navigate | Enter: expand / run command | Esc: quit"))
	b.WriteString("\n")

	return b.String()
}

// displayAmount returns the plain amount for own orders and cipher text for others.
func (m model) displayAmount(order core.Order) string {
	if plainAmt, ok := m.ownOrderIDs[order.ID]; ok {
		return plainAmt
	}
	amount := string(order.Amount)
	if len(amount) > 22 {
		amount = amount[:22] + "..."
	}
	return amount
}

// ────────────────────── Detail Panel ──────────────────────

func (m model) renderDetail(order core.Order) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Order ID:    %s\n", order.ID))

	typeStr := buyStyle.Render("BUY")
	if order.Type == core.Sell {
		typeStr = sellStyle.Render("SELL")
	}
	b.WriteString(fmt.Sprintf("Type:        %s\n", typeStr))
	b.WriteString(fmt.Sprintf("Pair:        %s\n", order.Subject.String()))

	priceStr := "-"
	if order.Price != nil {
		priceStr = order.Price.String()
	}
	b.WriteString(fmt.Sprintf("Price:       %s\n", priceStr))
	b.WriteString(fmt.Sprintf("Amount:      %s\n", m.displayAmount(order)))

	var statusStr string
	switch order.Status {
	case core.Pending:
		statusStr = "Pending"
	case core.Matched:
		statusStr = "Matched"
	case core.Done:
		statusStr = "Done"
	case core.Cancelled:
		statusStr = "Cancelled"
	default:
		statusStr = "Unknown"
	}
	b.WriteString(fmt.Sprintf("Status:      %s", statusStr))

	if len(order.Targets) > 0 {
		targets := make([]string, len(order.Targets))
		for i, t := range order.Targets {
			targets[i] = string(t)
		}
		b.WriteString(fmt.Sprintf("\nTargets:     [%s]", strings.Join(targets, ", ")))
	}

	return detailBorderStyle.Render(b.String())
}
