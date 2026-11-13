package main

import (
	"flag"

	"github.com/sirupsen/logrus"
	"github.com/yu-org/yu/apps/synchronizer"
	"github.com/yu-org/yu/core/startup"
	"github.com/yu-org/yu/core/state/sqlstate"

	"github.com/invisibook-lab/invisibook/account"
	"github.com/invisibook-lab/invisibook/config"
	"github.com/invisibook-lab/invisibook/consensus"
	"github.com/invisibook-lab/invisibook/core"
)

// main boots the Invisibook chain node: it loads kernel and core configs,
// constructs the configured consensus, Account, and OrderBook tripods, then starts
// the kernel.
func main() {
	cfgPath := flag.String("config", "cfg/chain.toml", "path to chain config file")
	coreCfgPath := flag.String("core-config", "cfg/core.toml", "path to core tripod config file")
	flag.Parse()

	yuCfg := startup.InitKernelConfigFromPath(*cfgPath)

	coreCfg, err := config.Load(*coreCfgPath)
	if err != nil {
		logrus.Fatal("loading core configuration: ", err)
	}
	// yu owns the SQL connection and state lifecycle configured in chain.toml.
	kernel := startup.InitKernel(yuCfg)
	stateDB, ok := startup.StateDB.(*sqlstate.State)
	if !ok {
		logrus.Fatal("Invisibook requires statedb_type = sql")
	}
	kernel.ChainEnv.BindState = recoveringBind(stateDB, kernel.Chain.GetCompactBlock, kernel.BindState)
	cash, tables, err := consensus.RegisterTables(stateDB)
	if err != nil {
		logrus.Fatal("registering state tables: ", err)
	}
	accountTri := account.NewAccount(&coreCfg.Account, cash)
	orderBookTri := core.NewOrderBook(&coreCfg.OrderBook, tables)
	selected, err := buildConsensus(coreCfg)
	if err != nil {
		logrus.Fatal("building consensus: ", err)
	}
	genesisTri, err := consensus.NewGenesis(&coreCfg.Consensus, stateDB, cash, &coreCfg.Account)
	if err != nil {
		logrus.Fatal("building genesis: ", err)
	}
	selected.start()

	// The shared genesis tripod defines the genesis block; the
	// kernel writes it before any InitChain runs.
	kernel.
		WithTripods(genesisTri, selected.tripod, accountTri, orderBookTri, synchronizer.NewSynchronizer(yuCfg.SyncMode)).
		Startup()
}
