package main

import (
	"flag"

	"github.com/yu-org/yu/apps/poa"
	"github.com/yu-org/yu/core/startup"

	"github.com/invisibook-lab/invisibook/core"
)

func main() {
	cfgPath := flag.String("config", "cfg/config.toml", "path to kernel config file")
	flag.Parse()

	yuCfg := startup.InitKernelConfigFromPath(*cfgPath)
	poaCfg := poa.DefaultCfg(0)

	poaTri := poa.NewPoa(poaCfg)
	orderBookTri := core.NewOrderBook()
	accountTri := core.NewAccount()

	startup.InitDefaultKernel(yuCfg).WithTripods(poaTri, orderBookTri, accountTri).Startup()
}
