package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/maestroi/Fleetguard/internal/controller/auth"
	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

// runNeverBan is a local operator command. No HTTP write endpoint exists.
func runNeverBan(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: never-ban add|renew|list|diff [flags]")
	}
	command := args[0]
	switch command {
	case "add", "renew", "list", "diff":
	default:
		return errors.New("unknown never-ban command; use add, renew, list or diff")
	}
	flags := flag.NewFlagSet("never-ban "+command, flag.ContinueOnError)
	configPath := flags.String("config", "", "controller server JSON")
	keyID := flags.String("key-id", "", "independent fleet-protection signing key ID")
	publicPath := flags.String("public-key", "", "fleet-protection public key")
	privatePath := flags.String("private-key", "", "fleet-protection private key (add/renew only)")
	reason := flags.String("reason", "", "operator change reason (add/renew only)")
	category := flags.String("category", "", "infrastructure|peers|partners|edge (add only)")
	ttl := flags.Duration("ttl", protocol.MaxNeverBanTTL, "signed protection validity (add/renew only)")
	from := flags.Uint64("from", 0, "previous revision for diff (0 = empty baseline)")
	revisionFlag := flags.Uint64("revision", 0, "historical revision for list (0 = latest)")
	file := flags.String("file", "", "bulk import: one canonical CIDR per line, # comments (add only)")
	dryRun := flags.Bool("dry-run", false, "validate an add against the latest revision without writing")
	var additions []protocol.Protection
	flags.Func("cidr", "canonical CIDR; repeat to add multiple (add only)", func(value string) error {
		if len(additions) >= protocol.MaxNeverBanEntries {
			return errors.New("too many CIDRs")
		}
		additions = append(additions, protocol.Protection{CIDR: value})
		return nil
	})
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *configPath == "" || *keyID == "" || *publicPath == "" {
		return errors.New("explicit -config, -key-id and -public-key required; no positional values")
	}
	if *file != "" {
		if command != "add" {
			return errors.New("-file is an add-only flag")
		}
		bulk, err := readCIDRFile(*file)
		if err != nil {
			return err
		}
		for _, cidr := range bulk {
			additions = append(additions, protocol.Protection{CIDR: cidr})
		}
		if len(additions) > protocol.MaxNeverBanEntries {
			return errors.New("too many CIDRs")
		}
	}
	if *dryRun && command != "add" {
		return errors.New("-dry-run is only supported by add")
	}
	write := (command == "add" && !*dryRun) || command == "renew"
	if (write || *dryRun) && *reason == "" {
		return errors.New("add/renew require -reason")
	}
	if write && (*privatePath == "" || *reason == "") {
		return errors.New("add/renew require -private-key and -reason")
	}
	if !write && !*dryRun && (*privatePath != "" || *reason != "" || *ttl != protocol.MaxNeverBanTTL) {
		return errors.New("write flags are not allowed on list/diff")
	}
	if command != "add" && (len(additions) != 0 || *category != "") {
		return errors.New("CIDRs and category are add-only flags")
	}
	if command == "add" && (len(additions) == 0 || *category == "") {
		return errors.New("add requires -category and at least one -cidr or -file")
	}
	if command != "list" && *revisionFlag != 0 {
		return errors.New("-revision is only supported by list")
	}
	if command != "diff" && *from != 0 {
		return errors.New("-from is only supported by diff")
	}
	invalid := map[string]string{}
	for i := range additions {
		additions[i].Category = protocol.ProtectionCategory(*category)
		if err := protocol.ValidateProtection(additions[i]); err != nil {
			invalid[additions[i].CIDR] = string(protocol.Reason(err))
		}
	}
	if len(invalid) > 0 && !*dryRun {
		return fmt.Errorf("invalid protections (use -dry-run for a full report): %v", invalid)
	}
	cfg, err := auth.LoadServer(*configPath)
	if err != nil {
		return err
	}
	if *keyID == cfg.SigningKeyID {
		return errors.New("fleet protection requires a distinct key ID from the policy signer")
	}
	pub, err := auth.LoadNeverBanPublicKey(*publicPath)
	if err != nil {
		return err
	}
	if cfg.NeverBanKeyID != "" {
		configured, err := auth.LoadNeverBanPublicKey(cfg.NeverBanPublicKeyFile)
		if err != nil {
			return err
		}
		if *keyID != cfg.NeverBanKeyID || !bytes.Equal(pub, configured) {
			return errors.New("CLI protection signer differs from configured distribution signer")
		}
	}
	keys := map[string]ed25519.PublicKey{*keyID: pub}
	var db *store.DB
	var key ed25519.PrivateKey
	if write {
		// Compare actual key material, not just IDs or file names.
		policyKey, err := auth.LoadSigningKey(cfg.SigningKeyFile)
		if err != nil {
			return err
		}
		if bytes.Equal(pub, policyKey.Public().(ed25519.PublicKey)) {
			return errors.New("fleet protection must use a different key from the policy signer")
		}
		key, err = auth.LoadSigningKey(*privatePath)
		if err != nil {
			return err
		}
		if !bytes.Equal(pub, key.Public().(ed25519.PublicKey)) {
			return errors.New("fleet-protection private and public keys do not match")
		}
		db, err = store.Open(cfg.DatabaseFile)
	} else {
		db, err = store.OpenReadOnly(cfg.DatabaseFile)
	}
	if err != nil {
		return err
	}
	defer db.Close()
	now := time.Now().UTC()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if write {
		// This is the real local process UID, not a caller-supplied identity.
		actor := "uid:" + strconv.Itoa(os.Getuid())
		revision, err := db.UpdateNeverBan(additions, command == "renew", actor, *reason, *keyID, key, now, *ttl)
		if err != nil {
			return err
		}
		return enc.Encode(revision)
	}
	if *dryRun {
		return neverBanDryRun(db, keys, additions, invalid, now, enc)
	}
	current, err := db.ReadNeverBanRevision(*revisionFlag, keys)
	if err != nil {
		return err
	}
	if command == "list" {
		return enc.Encode(struct {
			Revision store.NeverBanRevision `json:"revision"`
			Expired  bool                   `json:"expired"`
		}{current, !current.List.ExpiresAt.After(now)})
	}
	var previous protocol.NeverBanList
	if *from != 0 {
		rev, err := db.ReadNeverBanRevision(*from, keys)
		if err != nil {
			return err
		}
		previous = rev.List
	}
	added := make([]protocol.Protection, 0)
	if previous.Revision != current.List.Revision {
		added, err = store.NeverBanDiff(previous, current.List)
		if err != nil {
			return err
		}
	}
	return enc.Encode(struct {
		From   uint64                `json:"from_revision"`
		To     uint64                `json:"to_revision"`
		Added  []protocol.Protection `json:"added"`
		Actor  string                `json:"latest_actor"`
		Reason string                `json:"latest_reason"`
	}{previous.Revision, current.List.Revision, added, current.Actor, current.Reason})
}

// readCIDRFile reads a bounded operator-supplied list. It never resolves
// names; each non-comment line must be one CIDR.
func readCIDRFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(io.LimitReader(f, 1<<20))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(out) >= protocol.MaxNeverBanEntries {
			return nil, errors.New("CIDR file exceeds entry limit")
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

// neverBanDryRun reports what an add would change. It writes nothing and
// returns an error (non-zero exit) when the real add would be refused.
func neverBanDryRun(db *store.DB, keys map[string]ed25519.PublicKey, additions []protocol.Protection, invalid map[string]string, now time.Time, enc *json.Encoder) error {
	var latest protocol.NeverBanList
	current, err := db.ReadNeverBanRevision(0, keys)
	if err == nil {
		latest = current.List
	} else if !errors.Is(err, store.ErrNeverBanMissing) {
		return err
	}
	existing := make(map[protocol.Protection]bool, len(latest.Entries))
	for _, e := range latest.Entries {
		existing[e] = true
	}
	report := struct {
		CurrentRevision  uint64                `json:"current_revision"`
		CurrentExpired   bool                  `json:"current_expired"`
		Requested        int                   `json:"requested"`
		New              []protocol.Protection `json:"new"`
		DuplicateRequest int                   `json:"duplicate_in_request"`
		AlreadyProtected int                   `json:"already_protected"`
		Invalid          map[string]string     `json:"invalid"`
		ResultingEntries int                   `json:"resulting_entries"`
		OverLimit        bool                  `json:"over_limit"`
	}{CurrentRevision: latest.Revision, CurrentExpired: latest.Revision > 0 && !latest.ExpiresAt.After(now), Requested: len(additions), New: []protocol.Protection{}, Invalid: invalid}
	seen := map[protocol.Protection]bool{}
	for _, a := range additions {
		switch {
		case invalid[a.CIDR] != "":
		case seen[a]:
			report.DuplicateRequest++
		case existing[a]:
			report.AlreadyProtected++
		default:
			report.New = append(report.New, a)
		}
		seen[a] = true
	}
	report.ResultingEntries = len(latest.Entries) + len(report.New)
	report.OverLimit = report.ResultingEntries > protocol.MaxNeverBanEntries
	if err := enc.Encode(report); err != nil {
		return err
	}
	if len(invalid) > 0 || report.OverLimit || len(report.New) == 0 {
		return errors.New("dry-run: add would be refused")
	}
	return nil
}
