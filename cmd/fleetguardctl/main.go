package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/maestroi/Fleetguard/internal/lab"

	"github.com/maestroi/Fleetguard/internal/buildinfo"
	"github.com/maestroi/Fleetguard/internal/config"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fleetguardctl version | check-config -kind agent|controller -config FILE | simulate [-a FILE] [-b FILE] [-at RFC3339] | hash-token (stdin) | generate-signing-key -private FILE -public FILE")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "hash-token":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		token, err := io.ReadAll(io.LimitReader(os.Stdin, 258))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		value := strings.TrimSuffix(string(token), "\n")
		if len(value) < 32 || len(value) > 256 || strings.ContainsAny(value, "\r\n \t") {
			fmt.Fprintln(os.Stderr, "token must be 32-256 bytes without whitespace")
			os.Exit(2)
		}
		digest := sha256.Sum256([]byte(value))
		fmt.Println(hex.EncodeToString(digest[:]))
	case "generate-signing-key":
		flags := flag.NewFlagSet("generate-signing-key", flag.ExitOnError)
		private := flags.String("private", "", "output private Ed25519 key file (0600)")
		public := flags.String("public", "", "output public Ed25519 key file")
		flags.Parse(os.Args[2:])
		if flags.NArg() != 0 || *private == "" || *public == "" || *private == *public {
			usage()
			os.Exit(2)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err = os.MkdirAll(filepath.Dir(*private), 0700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		f, err := os.OpenFile(*private, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_, err = f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n")
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pubFile, err := os.OpenFile(*public, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_, err = pubFile.WriteString(base64.StdEncoding.EncodeToString(pub) + "\n")
		if closeErr := pubFile.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Ed25519 signing key pair generated; private key stays on controller")
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
