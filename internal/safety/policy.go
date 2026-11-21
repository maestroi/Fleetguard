// Package safety is the locally trusted authorization gate for signed firewall
// proposals. A signature proves origin, not permission to touch host networking.
package safety

import (
 "bytes"
 "crypto/ed25519"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/netip"
 "os"
 "regexp"
 "strings"
 "time"

 "github.com/maestroi/Fleetguard/internal/firewall"
 "github.com/maestroi/Fleetguard/pkg/protocol"
)

const maxPolicyBytes = 64 << 10

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$`)

// Policy must come from a local file, never from the controller or a snapshot.
// Enforce is a policy intent, NOT evidence that a backend is safe to use.
type Policy struct {
 Mode string `json:"mode"`
 ProtectedCIDRs []string `json:"protected_cidrs"`
 ManagementInterfaces []string `json:"management_interfaces"`
 ControllerIPs []string `json:"controller_ips"`
 ServiceScopes []ServiceScope `json:"service_scopes"`
 MaxDecisionTTLSeconds int `json:"max_decision_ttl_seconds"`
 MaxDecisions int `json:"max_decisions"`
}

type ServiceScope struct {
 ServiceGroup string `json:"service_group"`
 Service string `json:"service"`
 Transport protocol.Transport `json:"transport"`
 Ports []uint16 `json:"ports"`
}

// Rejection codes are intentionally stable and can be included in an agent's
// structured audit/acknowledgement without exposing local protection details.
type Rejection struct {
 Code string `json:"code"`
 DecisionID string `json:"decision_id,omitempty"`
 Detail string `json:"detail"`
}
func (e *Rejection) Error() string { return fmt.Sprintf("local safety %s: %s", e.Code, e.Detail) }
func reject(code, id, detail string) error { return &Rejection{Code:code, DecisionID:id, Detail:detail} }

// Runtime is host-derived, not remotely mutable. In particular, Verified is
// set only after the real adapter proves supported packet path/rule ordering.
type Runtime struct {
 BackendName string
 Verified bool
 Capabilities firewall.Capabilities
 Disabled bool
 // InterfacePrefixes can be injected in rootless tests. Nil uses host state.
 InterfacePrefixes func(string) ([]netip.Prefix, error)
}

// Parse accepts rootless fixture validation; enforcement must use LoadRootOwned
// to enforce filesystem ownership and prevent unprivileged local tampering.
func Parse(data []byte) (Policy,error) {
 var p Policy
 if len(data)>maxPolicyBytes { return p, fmt.Errorf("local policy exceeds %d bytes",maxPolicyBytes) }
 d:=json.NewDecoder(bytes.NewReader(data))
 d.DisallowUnknownFields()
 if err:=d.Decode(&p); err!=nil { return Policy{},fmt.Errorf("decode local policy: %w",err) }
 var extra any
 if err:=d.Decode(&extra); err!=io.EOF {
  if err==nil { return Policy{},errors.New("multiple JSON values in local policy") }
  return Policy{},fmt.Errorf("trailing local policy data: %w",err)
 }
 if err:=p.Validate(); err!=nil { return Policy{},err }
 return p,nil
}

func (p Policy) Validate() error {
 if p.Mode!="observe" && p.Mode!="enforce" { return errors.New("local policy mode must be observe or enforce") }
 if len(p.ProtectedCIDRs)==0 || len(p.ProtectedCIDRs)>128 { return errors.New("1-128 protected CIDRs required") }
 for _,raw:=range p.ProtectedCIDRs {
  prefix,err:=netip.ParsePrefix(raw)
  if err!=nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Masked()!=prefix || prefix.String()!=raw { return fmt.Errorf("invalid canonical protected CIDR %q",raw) }
 }
 if len(p.ManagementInterfaces)>16 { return errors.New("too many management interfaces") }
 for _,name:=range p.ManagementInterfaces {
  if !interfacePattern.MatchString(name) { return fmt.Errorf("invalid management interface %q",name) }
 }
 if len(p.ControllerIPs)>16 { return errors.New("too many controller IPs") }
 for _,raw:=range p.ControllerIPs {
  addr,err:=netip.ParseAddr(raw)
  if err!=nil || addr.Is4In6() || addr.IsUnspecified() || addr.IsMulticast() || addr.String()!=raw || addr.Zone()!="" { return fmt.Errorf("invalid controller IP %q",raw) }
 }
 if p.MaxDecisionTTLSeconds<=0 || p.MaxDecisionTTLSeconds>int(protocol.MaxSnapshotTTL/time.Second) { return errors.New("max_decision_ttl_seconds must be 1-300") }
 if p.MaxDecisions<=0 || p.MaxDecisions>protocol.MaxDecisions { return errors.New("max_decisions must be 1-256") }
 if len(p.ServiceScopes)==0 || len(p.ServiceScopes)>64 { return errors.New("1-64 explicit service scopes required") }
 seen:=map[string]bool{}
 for _,scope:=range p.ServiceScopes {
  if !namePattern.MatchString(scope.ServiceGroup) || !namePattern.MatchString(scope.Service) { return errors.New("invalid service scope identifier") }
  if scope.Transport!=protocol.TransportTCP && scope.Transport!=protocol.TransportUDP { return errors.New("invalid scope transport") }
  if len(scope.Ports)==0 || len(scope.Ports)>protocol.MaxPortsPerDecision { return errors.New("scope ports must have 1-16 entries") }
  prev:=uint16(0)
  for _,port:=range scope.Ports { if port<=prev { return errors.New("scope ports must be nonzero, sorted and unique") }; prev=port }
  key:=scope.ServiceGroup+"\x00"+scope.Service+"\x00"+string(scope.Transport)
  if seen[key] { return fmt.Errorf("duplicate scope for %s",scope.Service) };seen[key]=true
 }
 return nil
}

// VerifyAndAuthorize rejects the entire snapshot if any decision is unsafe.
// It MUST run before passing desired state to any firewall.Backend.
func VerifyAndAuthorize(envelope protocol.SignedSnapshot, keys map[string]ed25519.PublicKey, expected protocol.Audience, lastRevision uint64, now time.Time, policy Policy, runtime Runtime) (protocol.Snapshot,error) {
 snapshot,err:=protocol.VerifySignedSnapshot(envelope,keys,expected,lastRevision,now)
 if err!=nil { return protocol.Snapshot{},err }
 if err:=policy.Authorize(snapshot,expected,now,runtime);err!=nil { return protocol.Snapshot{},err }
 return snapshot,nil
}

// Authorize also validates unsigned in-memory proposals, but MUST NOT be used
// instead of VerifyAndAuthorize for controller-supplied snapshots.
func (p Policy) Authorize(s protocol.Snapshot, expected protocol.Audience, now time.Time, runtime Runtime) error {
 if err:=p.Validate(); err!=nil { return reject("invalid_local_policy","",err.Error()) }
 if err:=protocol.ValidateSnapshot(s);err!=nil { return err }
 if p.Mode!="enforce" { return reject("observe_only","","enforcement not opted in locally") }
 if runtime.Disabled { return reject("emergency_disabled","","local emergency kill switch is active") }
 if runtime.BackendName!="firewalld" || !runtime.Verified || runtime.Capabilities.Simulated || !runtime.Capabilities.IPv4 || !runtime.Capabilities.ScopedPorts {
  return reject("unverified_backend","","backend and port-scoped INPUT rule ordering must be independently verified")
 }
 if expected.NodeID=="" || expected.ServiceGroup=="" || s.Audience.ServiceGroup!=expected.ServiceGroup || (s.Audience.NodeID!="" && s.Audience.NodeID!=expected.NodeID) {
  return reject("audience_mismatch","","signed audience is outside this node/service group")
 }
 if !s.ExpiresAt.After(now) { return reject("expired","","snapshot expired") }
 if len(s.Decisions)>p.MaxDecisions { return reject("too_many_decisions","","local entry cap exceeded") }
 protected:=make([]netip.Prefix,0,len(p.ProtectedCIDRs)+len(p.ControllerIPs)+8)
 for _,raw:=range p.ProtectedCIDRs { prefix,_:=netip.ParsePrefix(raw);protected=append(protected,prefix) }
 for _,raw:=range p.ControllerIPs {
  ip,_:=netip.ParseAddr(raw)
  bits:=128
  if ip.Is4() {bits=32}
  protected=append(protected,netip.PrefixFrom(ip,bits))
 }
 probe:=runtime.InterfacePrefixes
 if probe==nil { probe=hostInterfacePrefixes }
 for _,name:=range p.ManagementInterfaces {
  prefixes,err:=probe(name)
  if err!=nil || len(prefixes)==0 { return reject("management_interface_unverified","","cannot establish protected management interface "+name) }
  for _,prefix:=range prefixes {
   if !prefix.IsValid() || prefix.Addr().Is4In6() { return reject("management_interface_unverified","","invalid management interface addresses") }
   protected=append(protected,prefix.Masked())
  }
 }
 for _,d:=range s.Decisions {
  src,err:=netip.ParsePrefix(d.Source)
  if err!=nil || !src.Addr().Is4() || src.Bits()!=32 || src.Masked()!=src { return reject("invalid_source",d.ID,"only IPv4 host /32 is allowed") }
  addr:=src.Addr()
  if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast() || strings.HasPrefix(addr.String(),"255.") {
   return reject("protected_source",d.ID,"system/reserved source cannot be blocked")
  }
  for _,prefix:=range protected {
   if prefix.Contains(addr) { return reject("protected_source",d.ID,"source overlaps a locally protected network") }
  }
  if !d.ExpiresAt.After(now) || d.ExpiresAt.Sub(now)>time.Duration(p.MaxDecisionTTLSeconds)*time.Second {
   return reject("ttl_exceeded",d.ID,"decision expired or exceeds local TTL cap")
  }
  allowed:=false
  for _,scope:=range p.ServiceScopes {
   if scope.ServiceGroup!=expected.ServiceGroup || scope.Service!=d.Service || scope.Transport!=d.Transport { continue }
   permitted:=true
   for _,port:=range d.DestinationPorts {
    found:=false
    for _,allowedPort:=range scope.Ports { if port==allowedPort {found=true;break} }
    if !found {permitted=false;break}
   }
   if permitted {allowed=true;break}
  }
  if !allowed { return reject("scope_denied",d.ID,"service, protocol or destination port not locally authorized") }
 }
 return nil
}

func hostInterfacePrefixes(name string) ([]netip.Prefix,error) {
 iface,err:=net.InterfaceByName(name)
 if err!=nil {return nil,err}
 if iface.Flags&net.FlagUp==0 {return nil,errors.New("management interface is down")}
 addrs,err:=iface.Addrs()
 if err!=nil {return nil,err}
 out:=make([]netip.Prefix,0,len(addrs))
 for _,a:=range addrs {
  prefix,err:=netip.ParsePrefix(a.String())
  if err!=nil {return nil,err}
  out=append(out,prefix)
 }
 return out,nil
}

// LoadRootOwned is for the future privileged agent enforcement path. The file
// and every ancestor must be root-owned and not group/world writable.
func LoadRootOwned(path string) (Policy,error) {
 if err:=checkRootPath(path,false);err!=nil { return Policy{},err }
 data,err:=os.ReadFile(path)
 if err!=nil {return Policy{},err}
 return Parse(data)
}
