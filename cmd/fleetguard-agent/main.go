package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/maestroi/Fleetguard/internal/agent"
	"github.com/maestroi/Fleetguard/internal/buildinfo"
	"github.com/maestroi/Fleetguard/internal/config"
	"github.com/maestroi/Fleetguard/internal/sim"
)

func main() {
	flags := flag.NewFlagSet("fleetguard-agent", flag.ExitOnError)
	configPath := flags.String("config", "", "path to local JSON configuration (required)")
	showVersion := flags.Bool("version", false, "print build version")
	run := flags.Bool("run", false, "run opt-in signed-policy polling and reconciliation daemon")
	runtimeConfig := flags.String("runtime-config", "", "absolute path to private runtime agent config (requires -run)")
	flags.Parse(os.Args[1:])
	if *showVersion {
		fmt.Println(buildinfo.String("fleetguard-agent"))
		return
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if *run {
		if *configPath != "" || *runtimeConfig == "" {
			fmt.Fprintln(os.Stderr, "use -run -runtime-config FILE, not bootstrap -config")
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := agent.Run(ctx, *runtimeConfig, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "fleetguard-agent:", err)
			os.Exit(1)
		}
		return
	}
	if *runtimeConfig != "" {
		fmt.Fprintln(os.Stderr, "-runtime-config requires -run")
		os.Exit(2)
	}
	c, err := config.LoadAgent(*configPath)
	if err == nil {
		err = sim.Agent(c, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fleetguard-agent:", err)
		os.Exit(1)
	}
}
