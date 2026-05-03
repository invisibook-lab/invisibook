package main

import (
	"flag"
	"log"

	"github.com/yu-org/yu/apps/poa"
	"github.com/yu-org/yu/core/startup"

	"github.com/invisibook-lab/invisibook/core"
)

// main boots the Invisibook chain node: it loads kernel and core configs,
// constructs the PoA, Account, and OrderBook tripods, then starts the kernel.
// `cfgPath` and `coreCfgPath` must point at readable TOML files (or core falls
// back to defaults if its file is missing/unreadable).
func main() {
	cfgPath := flag.String("config", "cfg/chain.toml", "path to chain config file")
	coreCfgPath := flag.String("core-config", "cfg/core.toml", "path to core tripod config file")
	flag.Parse()

	yuCfg := startup.InitKernelConfigFromPath(*cfgPath)
	poaCfg := poa.SingleNodeCfg()

	// Core config is optional: missing or malformed files fall back to defaults
	// so a fresh node can boot without a hand-written core.toml.
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
