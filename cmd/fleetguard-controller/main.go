package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/maestroi/Fleetguard/internal/buildinfo"
	"github.com/maestroi/Fleetguard/internal/config"
	"github.com/maestroi/Fleetguard/internal/sim"
)

func main() {
	flags := flag.NewFlagSet("fleetguard-controller", flag.ExitOnError)
	configPath := flags.String("config", "", "path to local JSON configuration (required)")
	showVersion := flags.Bool("version", false, "print build version")
	flags.Parse(os.Args[1:])
	if *showVersion {
		fmt.Println(buildinfo.String("fleetguard-controller"))
		return
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
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
