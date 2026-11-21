package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/maestroi/Fleetguard/internal/lab"

	"github.com/maestroi/Fleetguard/internal/buildinfo"
	"github.com/maestroi/Fleetguard/internal/config"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fleetguardctl version | check-config -kind agent|controller -config FILE | simulate [-a FILE] [-b FILE] [-at RFC3339]")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		fmt.Println(buildinfo.String("fleetguardctl"))
	case "simulate":
		flags := flag.NewFlagSet("simulate", flag.ExitOnError)
		aPath := flags.String("a", "examples/synthetic/node-a.json", "node A fixture")
		bPath := flags.String("b", "examples/synthetic/node-b.json", "node B fixture")
		atFlag := flags.String("at", "2026-11-21T12:00:00Z", "injected fixture clock (RFC3339)")
		flags.Parse(os.Args[2:])
		if flags.NArg() != 0 {
			usage()
			os.Exit(2)
		}
		at, err := time.Parse(time.RFC3339, *atFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid -at:", err)
			os.Exit(2)
		}
		a, err := os.Open(*aPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open node A:", err)
			os.Exit(1)
		}
		defer a.Close()
		b, err := os.Open(*bPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open node B:", err)
			os.Exit(1)
		}
		defer b.Close()
		report, err := lab.RunDemo(a, b, at)
		if err != nil {
			fmt.Fprintln(os.Stderr, "simulation failed:", err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "check-config":
		flags := flag.NewFlagSet("check-config", flag.ExitOnError)
		kind := flags.String("kind", "", "agent or controller")
		path := flags.String("config", "", "path to local JSON configuration")
		flags.Parse(os.Args[2:])
		if flags.NArg() != 0 {
			usage()
			os.Exit(2)
		}
		var err error
		switch *kind {
		case "agent":
			_, err = config.LoadAgent(*path)
		case "controller":
			_, err = config.LoadController(*path)
		default:
			fmt.Fprintln(os.Stderr, "-kind must be agent or controller")
			os.Exit(2)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid config:", err)
			os.Exit(1)
		}
		fmt.Printf("%s config valid (observe-only bootstrap)\n", *kind)
	default:
		usage()
		os.Exit(2)
	}
}
