package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/maestroi/Fleetguard/internal/buildinfo"
	"github.com/maestroi/Fleetguard/internal/config"
	"github.com/maestroi/Fleetguard/internal/controller/api"
	"github.com/maestroi/Fleetguard/internal/controller/auth"
	"github.com/maestroi/Fleetguard/internal/sim"
)

func main() {
	flags := flag.NewFlagSet("fleetguard-controller", flag.ExitOnError)
	configPath := flags.String("config", "", "path to local JSON configuration (required)")
	showVersion := flags.Bool("version", false, "print build version")
	serve := flags.Bool("serve", false, "start explicit private HTTPS observe-only controller; requires -config server JSON")
	flags.Parse(os.Args[1:])
	if *showVersion {
		fmt.Println(buildinfo.String("fleetguard-controller"))
		return
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if *serve {
		c, err := auth.LoadServer(*configPath)
		if err == nil {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			err = api.Run(ctx, c)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "fleetguard-controller:", err)
			os.Exit(1)
		}
		return
	}
	c, err := config.LoadController(*configPath)
	if err == nil {
		err = sim.Controller(c, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fleetguard-controller:", err)
		os.Exit(1)
	}
}
