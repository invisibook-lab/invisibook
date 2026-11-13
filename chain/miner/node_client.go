package miner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yu-org/yu/common"

	"github.com/invisibook-lab/invisibook/consensus"
)

// nodeStatusTimeout bounds one read of the node's payment status.
const nodeStatusTimeout = 2 * time.Second

// NodeClient is the console's view of the L2 node it mines for, over the
// node's payment listener: GET /payment_status for the book's state and
// POST /pay_l1_token for declarations. It is the Book and the Declarer the
// console runs on when it lives in pob-miner rather than in the node.
type NodeClient struct {
	baseURL string
	http    *http.Client

	// mu guards the last status the node answered with. A node that stops
	// answering keeps showing that rather than a zero height, which would
	// read as a fresh chain.
	mu   sync.Mutex
	last consensus.PaymentStatus
}

// NewNodeClient talks to the node whose payment listener is at `baseURL`,
// e.g. "http://127.0.0.1:8081".
func NewNodeClient(baseURL string) *NodeClient {
	return &NodeClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: time.Minute},
	}
}

// Consumed is the highest height the node has settled.
func (n *NodeClient) Consumed() common.BlockNum {
	return n.status().ConsumedHeight
}

// Pending is how many declared heights the node's book holds.
func (n *NodeClient) Pending() int {
	return n.status().Pending
}

// status asks the node for its book's state, falling back to the last answer
// when it cannot be reached.
func (n *NodeClient) status() consensus.PaymentStatus {
	ctx, cancel := context.WithTimeout(context.Background(), nodeStatusTimeout)
	defer cancel()

	var got consensus.PaymentStatus
	err := n.do(ctx, http.MethodGet, "/payment_status", nil, &got)

	n.mu.Lock()
	defer n.mu.Unlock()
	if err != nil {
		logrus.Warnf("miner: reading the node's payment status: %v", err)
		return n.last
	}
	n.last = got
	return got
}

// Declare posts `payments` to the node's book. A node that cannot be reached
// or answers with something other than a declaration result has every
// payment rejected with that reason, so the caller sees why nothing was
// accepted.
func (n *NodeClient) Declare(ctx context.Context, payments []consensus.PaymentDeclaration) consensus.PayL1TokenResponse {
	var resp consensus.PayL1TokenResponse
	err := n.do(ctx, http.MethodPost, "/pay_l1_token", consensus.PayL1TokenRequest{Payments: payments}, &resp)
	if err == nil || len(resp.Accepted)+len(resp.Rejected) > 0 {
		// A refused batch comes back as 400 with the reasons in the body;
		// those are the answer, not a transport failure.
		return resp
	}
	rejected := make([]consensus.RejectedDeclaration, len(payments))
	for i, p := range payments {
		rejected[i] = consensus.RejectedDeclaration{BlockHeight: p.BlockHeight, Error: err.Error()}
	}
	return consensus.PayL1TokenResponse{Rejected: rejected}
}

// do sends one JSON request and decodes the reply into `out`. The body is
// decoded even on an error status, since the node explains refusals in it.
func (n *NodeClient) do(ctx context.Context, method, path string, in, out any) error {
	var body bytes.Buffer
	if in != nil {
		if err := json.NewEncoder(&body).Encode(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, n.baseURL+path, &body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := n.http.Do(req)
	if err != nil {
		return fmt.Errorf("reaching the node at %s: %w", n.baseURL, err)
	}
	defer resp.Body.Close()

	decodeErr := json.NewDecoder(resp.Body).Decode(out)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the node answered %s %s with %s", method, path, resp.Status)
	}
	return decodeErr
}

// Compile-time checks that NodeClient serves as both halves of the node the
// console needs.
var (
	_ Book     = (*NodeClient)(nil)
	_ Declarer = (*NodeClient)(nil)
)
