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
	orders      []core.Order
	ownOrderIDs map[core.OrderID]string // own order ID -> plain amount
	cursor      int
	expanded    int // -1 = nothing expanded
	input       textinput.Model
	message     string
	isError     bool
}

// per-position suggestions for the command input.
var (
	actionSuggestions = []string{"buy", "sell"}
	tokenSuggestions  = []string{"ETH", "BTC", "SOL", "USDT", "USDC", "DAI"}
)

func newModel() model {
	ti := textinput.New()
	ti.Placeholder = "buy/sell {token_1} {price} {amount} {token_2}"
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 56
	ti.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4")).Bold(true)
	ti.Prompt = "❯ "
	ti.SetSuggestions(actionSuggestions)
	ti.ShowSuggestions = true

	orders := sampleOrders()
	sortOrders(orders)

	return model{
		orders:      orders,
		ownOrderIDs: make(map[core.OrderID]string),
		cursor:      0,
		expanded:    -1,
		input:       ti,
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

	// dynamically update suggestions based on current input context
	m.input.SetSuggestions(contextSuggestions(m.input.Value()))

	return m, cmd
}

// contextSuggestions returns position-aware suggestions:
//
//	pos 0 (action):  buy / sell
//	pos 1 (token_1): token names
//	pos 2 (price):   no suggestions (user types a number)
//	pos 3 (amount):  no suggestions (user types a number)
//	pos 4 (token_2): token names
func contextSuggestions(value string) []string {
	parts := strings.Split(value, " ")
	pos := len(parts) - 1 // index of the word being typed
	prefix := ""
	if pos > 0 {
		prefix = strings.Join(parts[:pos], " ") + " "
	}

	var pool []string
	switch pos {
	case 0:
		pool = actionSuggestions
	case 1, 4:
		pool = tokenSuggestions
	default:
		return nil // numbers – no suggestions
	}

	out := make([]string, 0, len(pool))
	for _, s := range pool {
		out = append(out, prefix+s)
	}
	return out
}
