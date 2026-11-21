package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/maestroi/Fleetguard/internal/buildinfo"
	"github.com/maestroi/Fleetguard/internal/config"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fleetguardctl version | check-config -kind agent|controller -config FILE")
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
