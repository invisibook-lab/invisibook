package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/invisibook-lab/invisibook/core"
)

// ────────────────────── Model ──────────────────────

type model struct {
	orders   []core.Order
	cursor   int
	expanded int // -1 = nothing expanded
	input    textinput.Model
	message  string
	isError  bool
}

func newModel() model {
	ti := textinput.New()
	ti.Placeholder = "buy/sell {token_1} {amount_1} {token_2} {amount_2}"
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 56
	ti.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4")).Bold(true)
	ti.Prompt = "❯ "

	orders := sampleOrders()
	sortOrders(orders)

	return model{
		orders:   orders,
		cursor:   0,
		expanded: -1,
		input:    ti,
	}
}

// ────────────────────── Tea: Init / Update ──────────────────────

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit

		case tea.KeyUp:
			if m.cursor > 0 {
				m.cursor--
				m.expanded = -1
			}
			return m, nil

		case tea.KeyDown:
			if m.cursor < len(m.orders)-1 {
				m.cursor++
				m.expanded = -1
			}
			return m, nil

		case tea.KeyEnter:
			input := strings.TrimSpace(m.input.Value())
			if input != "" {
				m = m.handleCommand(input)
				m.input.SetValue("")
				return m, nil
			}
			// toggle expand / collapse
			if m.expanded == m.cursor {
				m.expanded = -1
			} else {
				m.expanded = m.cursor
			}
			return m, nil
		}
	}

	// forward everything else to the text input
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}
