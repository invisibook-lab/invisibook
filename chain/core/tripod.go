package core

import (
	"github.com/yu-org/yu/core/context"
	"github.com/yu-org/yu/core/tripod"
)

type OrderTri struct {
	*tripod.Tripod
}

func NewOrderTri() *OrderTri {
	tri := tripod.NewTripodWithName("core")
	ot := &OrderTri{tri}
	ot.SetWritings(ot.AddOrders, ot.CancelOrders)
	ot.SetReadings(ot.QueryOrders)
	return ot
}

type AddOrdersRequest struct {
	Orders []*Order `json:"orders"`
}

func (ot *OrderTri) AddOrders(ctx *context.WriteContext) error {
	req := new(AddOrdersRequest)
	err := ctx.BindJson(req)
	if err != nil {
		return err
	}

	return nil
}

func (ot *OrderTri) QueryOrders(ctx *context.ReadContext) {

}

type CancelOrdersRequest struct {
	Orders []OrderID `json:"orders"`
}

func (ot *OrderTri) CancelOrders(ctx *context.WriteContext) error {
	req := new(CancelOrdersRequest)
	err := ctx.BindJson(req)
	if err != nil {
		return err
	}

	return nil
}
