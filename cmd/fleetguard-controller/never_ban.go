package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
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

func loadNeverBanPublicKey(path string) (ed25519.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		return nil, err
	}
	if len(raw) > 256 {
		return nil, errors.New("never-ban public key file exceeds limit")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("expected base64 Ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}

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
	write := command == "add" || command == "renew"
	if write && (*privatePath == "" || *reason == "") {
		return errors.New("add/renew require -private-key and -reason")
	}
	if !write && (*privatePath != "" || *reason != "" || *ttl != protocol.MaxNeverBanTTL) {
		return errors.New("write flags are not allowed on list/diff")
	}
	if command != "add" && (len(additions) != 0 || *category != "") {
		return errors.New("CIDRs and category are add-only flags")
	}
	if command == "add" && (len(additions) == 0 || *category == "") {
		return errors.New("add requires -category and at least one -cidr")
	}
	if command != "list" && *revisionFlag != 0 {
		return errors.New("-revision is only supported by list")
	}
	if command != "diff" && *from != 0 {
		return errors.New("-from is only supported by diff")
	}
	for i := range additions {
		additions[i].Category = protocol.ProtectionCategory(*category)
	}
	cfg, err := auth.LoadServer(*configPath)
	if err != nil {
		return err
	}
	if *keyID == cfg.SigningKeyID {
		return errors.New("fleet protection requires a distinct key ID from the policy signer")
	}
	pub, err := loadNeverBanPublicKey(*publicPath)
	if err != nil {
		return err
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
