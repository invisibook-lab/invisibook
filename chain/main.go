package main

import (
	"flag"
	"log"

	"github.com/yu-org/yu/apps/poa"
	"github.com/yu-org/yu/core/startup"

	"github.com/invisibook-lab/invisibook/core"
)

func main() {
	cfgPath := flag.String("config", "cfg/chain.toml", "path to chain config file")
	coreCfgPath := flag.String("core-config", "cfg/core.toml", "path to core tripod config file")
	flag.Parse()

	yuCfg := startup.InitKernelConfigFromPath(*cfgPath)
	poaCfg := poa.SingleNodeCfg()

	coreCfg, err := core.LoadConfig(*coreCfgPath)
	if err != nil {
		log.Printf("WARN: failed to load core config (%s), using defaults: %v", *coreCfgPath, err)
		coreCfg = core.DefaultConfig()
	}

	poaTri := poa.NewPoa(poaCfg)
	accountTri := core.NewAccount(&coreCfg.Account)
	orderBookTri := core.NewOrderBook(&coreCfg.OrderBook)

	startup.InitDefaultKernel(yuCfg).WithTripods(poaTri, accountTri, orderBookTri).Startup()
}
