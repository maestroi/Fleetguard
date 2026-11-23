package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/maestroi/Fleetguard/internal/buildinfo"
	"github.com/maestroi/Fleetguard/internal/config"
	"github.com/maestroi/Fleetguard/internal/controller/api"
	"github.com/maestroi/Fleetguard/internal/controller/auth"
	"github.com/maestroi/Fleetguard/internal/controller/correlation"
	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/internal/sim"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

func main() {
	flags := flag.NewFlagSet("fleetguard-controller", flag.ExitOnError)
	configPath := flags.String("config", "", "path to local JSON configuration (required)")
	showVersion := flags.Bool("version", false, "print build version")
	evaluate := flags.Bool("evaluate", false, "offline, observe-only correlation report (no policy publication)")
	approve := flags.String("approve-lab-candidate", "", "publish this fresh correlation candidate ID to its reporting lab nodes")
	labCIDR := flags.String("lab-source-cidr", "", "explicit lab source subnet for approval")
	policyPath := flags.String("correlation", "", "private local correlation policy (required with -evaluate)")
	groupFlag := flags.String("group", "", "authorized service group (required with -evaluate and -inspect-node)")
	nodeFlag := flags.String("node", "", "node ID (required with -inspect-node)")
	inspectNode := flags.Bool("inspect-node", false, "local-only, read-only controller view of node evidence, signed policy and acknowledgements")
	purgeSensitive := flags.Bool("purge-sensitive", false, "local-only purge evidence and audit text past configured retention")
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
	if *approve != "" || *labCIDR != "" {
		if !*evaluate || *inspectNode || *purgeSensitive || *labCIDR == "" {
			fmt.Fprintln(os.Stderr, "lab evaluation requires -evaluate and -lab-source-cidr")
			os.Exit(2)
		}
	}
	if *inspectNode || *purgeSensitive {
		if *serve || *evaluate || (*inspectNode && *purgeSensitive) || *configPath == "" {
			fmt.Fprintln(os.Stderr, "inspection/purge is offline only and requires server -config")
			os.Exit(2)
		}
		c, err := auth.LoadServer(*configPath)
		if err == nil {
			if _, statErr := os.Stat(c.DatabaseFile); statErr != nil {
				err = statErr
			}
		}
		if err == nil {
			var db *store.DB
			if *inspectNode {
				db, err = store.OpenReadOnly(c.DatabaseFile)
			} else {
				db, err = store.Open(c.DatabaseFile)
			}
			if err == nil {
				defer db.Close()
				err = db.SetEvidenceRetention(c.EvidenceRetentionHours)
				if err == nil && *purgeSensitive {
					var purged store.RetentionPurge
					purged, err = db.PurgeSensitive(time.Now().UTC())
					if err == nil {
						err = json.NewEncoder(os.Stdout).Encode(purged)
					}
				}
				if err == nil && *inspectNode {
					if *nodeFlag == "" || *groupFlag == "" {
						err = fmt.Errorf("-inspect-node requires -node and -group")
					}
					if err == nil {
						var registry auth.Registry
						registry, err = auth.LoadRegistry(c.RegistryFile)
						if err == nil {
							allowed := false
							for _, node := range registry.Nodes {
								if node.NodeID != *nodeFlag {
									continue
								}
								for _, g := range node.Groups {
									if g == *groupFlag {
										allowed = true
									}
								}
							}
							if !allowed {
								err = fmt.Errorf("node is not assigned to requested group")
							}
						}
					}
					if err == nil {
						var report store.NodeAudit
						report, err = db.ReadNodeAudit(*nodeFlag, *groupFlag, 32)
						if err == nil {
							err = json.NewEncoder(os.Stdout).Encode(report)
						}
					}
				}
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "operator audit:", err)
			os.Exit(1)
		}
		return
	}
	if *evaluate {
		if *serve || *groupFlag == "" || *policyPath == "" {
			fmt.Fprintln(os.Stderr, "-evaluate requires -config, -correlation, -group and cannot be combined with -serve")
			os.Exit(2)
		}
		err := evaluateOffline(*configPath, *policyPath, *groupFlag, *approve, *labCIDR, os.Stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fleetguard-controller:", err)
			os.Exit(1)
		}
		return
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

// evaluateOffline reads the controller's local evidence and correlation policy.
// A named lab approval explicitly authorizes writing signed snapshots.
func evaluateOffline(serverPath, policyPath, group, approval, labCIDR string, out io.Writer) error {
	cfg, err := auth.LoadServer(serverPath)
	if err != nil {
		return err
	}
	policy, err := correlation.Load(policyPath)
	if err != nil {
		return err
	}
	if group != policy.Group {
		return fmt.Errorf("requested group does not match correlation policy")
	}
	registry, err := auth.LoadRegistry(cfg.RegistryFile)
	if err != nil {
		return err
	}
	for _, scope := range policy.Scopes {
		g, ok := registry.Groups[group]
		if !ok {
			return fmt.Errorf("unknown group")
		}
		permitted := false
		for _, s := range g.Services {
			if s == scope.Service {
				permitted = true
				break
			}
		}
		if !permitted {
			return fmt.Errorf("correlation scope not permitted in registry: %s", scope.Service)
		}
	}
	db, err := store.Open(cfg.DatabaseFile)
	if err != nil {
		return err
	}
	defer db.Close()
	now := time.Now().UTC()
	events, err := db.GroupEvidence(group, now.Add(-time.Duration(policy.WindowSeconds)*time.Second-protocol.MaxClockSkew), policy.MaxEvidence)
	if err != nil {
		_ = db.AuditEvaluation(group, 0, "read_error", now)
		return err
	}
	var report correlation.Report
	if labCIDR == "" {
		report, err = correlation.Evaluate(policy, registry, events, now)
	} else {
		var prefix netip.Prefix
		prefix, err = netip.ParsePrefix(labCIDR)
		if err == nil {
			report, err = correlation.EvaluateLab(policy, registry, events, now, prefix)
		}
	}
	if err != nil {
		_ = db.AuditEvaluation(group, 0, "rejected", now)
		return err
	}
	for _, candidate := range report.Candidates {
		// A shared-NAT candidate intentionally has no proposed Decision. Audit the
		// source/scope without constructing or publishing an enforceable decision.
		d := protocol.Decision{Source: candidate.Source + "/32", Service: candidate.Service, Transport: candidate.Transport, DestinationPorts: []uint16{candidate.Port}}
		if err := db.AuditCandidate(group, d, candidate.Status, candidate.ReasonCode, now); err != nil {
			return err
		}
	}
	if err := db.AuditEvaluation(group, len(report.Candidates), "observe_only", now); err != nil {
		return err
	}
	if approval != "" {
		for _, candidate := range report.Candidates {
			if candidate.Decision == nil || candidate.Decision.ID != approval {
				continue
			}
			ip := netip.MustParseAddr(candidate.Source)
			listener, err := netip.ParseAddrPort(cfg.Listen)
			if err != nil || ip == listener.Addr() {
				return fmt.Errorf("candidate source is the controller or its listener is invalid")
			}
			key, err := auth.LoadSigningKey(cfg.SigningKeyFile)
			if err != nil {
				return err
			}
			if err := db.PublishApprovedDecision(group, candidate.Nodes, *candidate.Decision, cfg.SigningKeyID, key, now); err != nil {
				return err
			}
			report.PublishedPolicies = len(candidate.Nodes)
			break
		}
		if report.PublishedPolicies == 0 {
			return fmt.Errorf("no eligible fresh correlation candidate with ID %q", approval)
		}
		report.Mode = "operator_approved_lab"
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
