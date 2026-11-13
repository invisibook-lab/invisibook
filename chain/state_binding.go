package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/common/yerror"
	"github.com/yu-org/yu/core/env"
	"github.com/yu-org/yu/core/state/sqlstate"
	"github.com/yu-org/yu/core/types"
)

// recoveringBind replaces only an identical orphaned version left between state binding and block append.
// lookup must distinguish ErrBlockNotFound from database failures; bind retains yu receipt persistence.
func recoveringBind(s *sqlstate.State, lookup func(common.Hash) (*types.CompactBlock, error), bind env.ExecuteFn) env.ExecuteFn {
	return func(block *types.Block) error {
		root, err := s.Store.Root(block.Hash.String())
		if err != nil && !errors.Is(err, sqlstate.ErrVersionUnavailable) {
			return err
		}
		if err == nil {
			if !bytes.Equal(root, block.StateRoot.Bytes()) {
				return fmt.Errorf("existing block state root mismatch")
			}
			_, lookupErr := lookup(block.Hash)
			if !errors.Is(lookupErr, yerror.ErrBlockNotFound) {
				if lookupErr != nil {
					return lookupErr
				}
				return fmt.Errorf("refusing to replace state for an appended block")
			}
			if err := s.Store.DropPending(block.Hash.String()); err != nil {
				return err
			}
		}
		return bind(block)
	}
}
