package miner

import (
	"crypto/subtle"
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yu-org/yu/common"
)

// indexHTML is the browser console, served at the root of the payment
// listener. One self-contained file: no build step and nothing fetched from
// elsewhere, since it handles a miner's money.
//
//go:embed web/index.html
var indexHTML []byte

// API is the HTTP face of Service: the endpoints the browser console calls.
type API struct {
	svc *Service
	// token, when non-empty, is the bearer token every /pob call must carry.
	// When empty the endpoints answer loopback callers only.
	token string
}

// NewAPI builds the console API over `svc`. `token` may be empty.
func NewAPI(svc *Service, token string) *API {
	return &API{svc: svc, token: token}
}

// Mount adds the console page and the /pob endpoints to `r`.
//
// The endpoints spend the miner's CKB, so they are guarded (see guard); the
// page itself is static and open, since it holds nothing.
func (a *API) Mount(r gin.IRouter) {
	r.GET("/", a.index)

	pob := r.Group("/pob", a.guard)
	pob.GET("/status", a.status)
	pob.GET("/prepayments", a.prepayments)
	pob.POST("/plan", a.plan)
	pob.POST("/prepay", a.prepay)
	pob.POST("/declare", a.declare)
}

// index serves the console page.
func (a *API) index(c *gin.Context) {
	c.Header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
	c.Data(http.StatusOK, "text/html; charset=utf-8", indexHTML)
}

// guard admits a request to the money-moving endpoints.
//
// With a token configured, that token is the only test. Without one the
// request has to come from this machine, addressed to this machine: checking
// the peer alone would let a hostile web page reach a loopback listener
// through DNS rebinding, and checking the Host alone would trust a header the
// caller writes. Writes must also be JSON, which a cross-site form cannot
// send without a CORS preflight this server never approves.
//
// The peer is read from the socket, not from gin's ClientIP, which believes
// X-Forwarded-For.
func (a *API) guard(c *gin.Context) {
	if a.token != "" {
		got := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
			abort(c, http.StatusUnauthorized, errors.New("missing or wrong bearer token"))
			return
		}
	} else if !fromLoopback(c.Request) {
		abort(c, http.StatusForbidden,
			errors.New("the miner console answers this machine only; set miner_api_token to open it further"))
		return
	}

	if c.Request.Method == http.MethodPost &&
		!strings.HasPrefix(c.GetHeader("Content-Type"), "application/json") {
		abort(c, http.StatusUnsupportedMediaType, errors.New("send application/json"))
		return
	}
	c.Next()
}

// fromLoopback reports whether the request arrived from a loopback address
// and was addressed to a loopback name.
func fromLoopback(r *http.Request) bool {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	if ip := net.ParseIP(peer); ip == nil || !ip.IsLoopback() {
		return false
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// abort ends the request with a JSON error.
func abort(c *gin.Context, status int, err error) {
	c.AbortWithStatusJSON(status, gin.H{"error": err.Error()})
}

// status handles GET /pob/status.
func (a *API) status(c *gin.Context) {
	c.JSON(http.StatusOK, a.svc.Status(c.Request.Context()))
}

// ─────────────────────────────── plan & prepay ───────────────────────────────

// allocationIn is one row of a manual table as the console sends it.
type allocationIn struct {
	Height    uint32 `json:"height"`
	AmountCKB string `json:"amount_ckb"`
}

// planBody is the request body of POST /pob/plan and, embedded, of
// POST /pob/prepay.
type planBody struct {
	// Mode is "random" (the default), "even" or "manual".
	Mode string `json:"mode"`
	// From and Count pick a run of consecutive heights; TotalCKB is what to
	// divide among them. Used by "random" and "even".
	From     uint32 `json:"from"`
	Count    uint32 `json:"count"`
	TotalCKB string `json:"total_ckb"`
	// SpreadPercent is how far a random share may stray from the mean; zero
	// means the default of 50.
	SpreadPercent uint32 `json:"spread_percent"`
	// Allocations is the table itself, for "manual".
	Allocations []allocationIn `json:"allocations"`
}

// toRequest converts the wire form, where amounts are decimal CKB, into a
// PlanRequest in shannon.
func (b planBody) toRequest() (PlanRequest, error) {
	req := PlanRequest{Mode: Mode(b.Mode), From: b.From, Count: b.Count}
	if req.Mode == "" {
		req.Mode = ModeRandom
	}
	if b.SpreadPercent > 99 {
		return req, errors.New("spread_percent must be below 100")
	}
	req.SpreadBps = b.SpreadPercent * 100

	if req.Mode == ModeManual {
		for _, row := range b.Allocations {
			amount, err := ParseCKB(row.AmountCKB)
			if err != nil {
				return req, fmt.Errorf("height %d: %w", row.Height, err)
			}
			req.Manual = append(req.Manual, Allocation{Height: row.Height, Amount: amount})
		}
		return req, nil
	}

	total, err := ParseCKB(b.TotalCKB)
	if err != nil {
		return req, errors.New("total_ckb: " + err.Error())
	}
	req.Total = total
	return req, nil
}

// allocationOut is one row of a plan as the console receives it.
type allocationOut struct {
	Height        uint32 `json:"height"`
	AmountShannon string `json:"amount_shannon"`
	AmountCKB     string `json:"amount_ckb"`
}

// planOut is a plan and its total.
type planOut struct {
	Allocations   []allocationOut `json:"allocations"`
	TotalShannon  string          `json:"total_shannon"`
	TotalCKB      string          `json:"total_ckb"`
	SuggestedFrom uint64          `json:"suggested_from"`
}

// plan handles POST /pob/plan: divide a prepayment and show the table without
// paying anything.
func (a *API) plan(c *gin.Context) {
	var body planBody
	if err := c.ShouldBindJSON(&body); err != nil {
		abort(c, http.StatusBadRequest, err)
		return
	}
	plan, err := a.buildPlan(body)
	if err != nil {
		abort(c, http.StatusBadRequest, err)
		return
	}

	out := planOut{
		Allocations:   make([]allocationOut, len(plan)),
		SuggestedFrom: a.svc.Status(c.Request.Context()).SuggestedFrom,
	}
	for i, alloc := range plan {
		out.Allocations[i] = allocationOut{
			Height:        alloc.Height,
			AmountShannon: alloc.Amount.String(),
			AmountCKB:     FormatCKB(alloc.Amount),
		}
	}
	total := PlanTotal(plan)
	out.TotalShannon, out.TotalCKB = total.String(), FormatCKB(total)
	c.JSON(http.StatusOK, out)
}

// buildPlan turns a request body into a checked plan.
func (a *API) buildPlan(body planBody) ([]Allocation, error) {
	req, err := body.toRequest()
	if err != nil {
		return nil, err
	}
	return a.svc.Plan(req)
}

// prepayBody is the request body of POST /pob/prepay.
type prepayBody struct {
	planBody
	// AutoDeclare declares the openings once the prepayment is committed.
	// Defaults to true.
	AutoDeclare *bool `json:"auto_declare"`
}

// prepay handles POST /pob/prepay: pay on L1 and allocate. It answers as soon
// as the openings are saved; the L1 transaction is followed in the
// background and shows up in GET /pob/prepayments.
func (a *API) prepay(c *gin.Context) {
	var body prepayBody
	if err := c.ShouldBindJSON(&body); err != nil {
		abort(c, http.StatusBadRequest, err)
		return
	}
	plan, err := a.buildPlan(body.planBody)
	if err != nil {
		abort(c, http.StatusBadRequest, err)
		return
	}
	autoDeclare := body.AutoDeclare == nil || *body.AutoDeclare

	p, err := a.svc.Prepay(plan, autoDeclare)
	if errors.Is(err, ErrNoL1) {
		abort(c, http.StatusServiceUnavailable, err)
		return
	}
	if err != nil {
		abort(c, http.StatusBadRequest, err)
		return
	}
	c.JSON(http.StatusAccepted, a.view(p, a.svc.book.Consumed(), 0, false))
}

// ─────────────────────────────── declare & list ───────────────────────────────

// declareBody is the request body of POST /pob/declare.
type declareBody struct {
	PrepaymentID string `json:"prepayment_id"`
	// From skips heights below it; zero declares everything still open.
	From uint32 `json:"from"`
}

// declare handles POST /pob/declare: hand a prepayment's openings to the node.
func (a *API) declare(c *gin.Context) {
	var body declareBody
	if err := c.ShouldBindJSON(&body); err != nil {
		abort(c, http.StatusBadRequest, err)
		return
	}
	resp, err := a.svc.Declare(body.PrepaymentID, body.From)
	if err != nil {
		abort(c, http.StatusBadRequest, err)
		return
	}
	if len(resp.Rejected) > 0 {
		c.JSON(http.StatusBadRequest, resp)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// prepayments handles GET /pob/prepayments.
func (a *API) prepayments(c *gin.Context) {
	list := a.svc.Prepayments()
	consumed := a.svc.book.Consumed()
	tip, tipKnown := a.svc.L1Tip(c.Request.Context())
	out := make([]prepaymentView, len(list))
	for i, p := range list {
		out[i] = a.view(p, consumed, tip, tipKnown)
	}
	c.JSON(http.StatusOK, gin.H{"prepayments": out})
}

// bidView is one height of a prepayment as the console sees it. The blinding
// factor is deliberately absent: it never leaves the node.
type bidView struct {
	Height        uint32 `json:"height"`
	AmountShannon string `json:"amount_shannon"`
	AmountCKB     string `json:"amount_ckb"`
	// State is pending (prepayment not yet committed), maturing (committed
	// but inside the payment lead), prepaid, declared, passed (declared, and
	// the chain has moved beyond it) or missed (the chain moved beyond it
	// before it was declared).
	State string `json:"state"`
}

// prepaymentView is a prepayment as the console sees it.
type prepaymentView struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	Status       string    `json:"status"`
	Error        string    `json:"error,omitempty"`
	TotalShannon string    `json:"total_shannon"`
	TotalCKB     string    `json:"total_ckb"`
	TxHash       string    `json:"tx_hash,omitempty"`
	L1Block      uint64    `json:"l1_block,omitempty"`
	// MaturesAt is the L1 block from which the openings may be declared.
	MaturesAt   uint64    `json:"matures_at,omitempty"`
	AutoDeclare bool      `json:"auto_declare"`
	Bids        []bidView `json:"bids"`
}

// view converts a stored prepayment to its console form, working out each
// bid's state against the chain's settled height and, when `tipKnown`, L1's
// tip.
func (a *API) view(p Prepayment, consumed common.BlockNum, tip uint64, tipKnown bool) prepaymentView {
	total, _ := new(big.Int).SetString(p.Total, 10)
	if total == nil {
		total = new(big.Int)
	}
	v := prepaymentView{
		ID:           p.ID,
		CreatedAt:    p.CreatedAt,
		Status:       string(p.Status),
		Error:        p.Error,
		TotalShannon: p.Total,
		TotalCKB:     FormatCKB(total),
		TxHash:       p.TxHash,
		L1Block:      p.L1Block,
		AutoDeclare:  p.AutoDeclare,
		Bids:         make([]bidView, len(p.Bids)),
	}
	if p.L1Block != 0 {
		v.MaturesAt = MaturesAt(p.L1Block)
	}
	maturing := p.Status == StatusConfirmed && tipKnown && tip < v.MaturesAt
	for i, b := range p.Bids {
		amount, _ := new(big.Int).SetString(b.Amount, 10)
		if amount == nil {
			amount = new(big.Int)
		}
		state := "pending"
		switch {
		case p.Status != StatusConfirmed:
		case uint64(b.Height) <= uint64(consumed) && b.Declared:
			state = "passed"
		case uint64(b.Height) <= uint64(consumed):
			state = "missed"
		case b.Declared:
			state = "declared"
		case maturing:
			state = "maturing"
		default:
			state = "prepaid"
		}
		v.Bids[i] = bidView{Height: b.Height, AmountShannon: b.Amount, AmountCKB: FormatCKB(amount), State: state}
	}
	return v
}
