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
// `cfgPath` and `coreCfgPath` must point at readable, well-formed TOML files.
// A missing or malformed core config is FATAL: falling back to defaults would
// silently disable proof verification (defaults carry no verifying keys), so
// the node refuses to start instead. Dev mode (no proof verification) must be
// requested explicitly with `require_proofs = false` in the config file.
func main() {
	cfgPath := flag.String("config", "cfg/chain.toml", "path to chain config file")
	coreCfgPath := flag.String("core-config", "cfg/core.toml", "path to core tripod config file")
	flag.Parse()

	yuCfg := startup.InitKernelConfigFromPath(*cfgPath)
	poaCfg := poa.SingleNodeCfg()

	coreCfg, err := core.LoadConfig(*coreCfgPath)
	if err != nil {
		log.Fatalf("FATAL: failed to load core config (%s): %v\n"+
			"Refusing to start: a default configuration would skip all ZK proof "+
			"verification. Fix the config file or pass --core-config.", *coreCfgPath, err)
	}

	poaTri := poa.NewPoa(poaCfg)
	accountTri := core.NewAccount(&coreCfg.Account)
	orderBookTri := core.NewOrderBook(&coreCfg.OrderBook)

	startup.InitDefaultKernel(yuCfg).WithTripods(poaTri, accountTri, orderBookTri).Startup()
}
