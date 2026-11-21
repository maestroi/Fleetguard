package agent

import (
 "bytes"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/netip"
 "net/url"
 "os"
 "path/filepath"
 "strings"
 "time"

 "github.com/maestroi/Fleetguard/internal/firewall/firewalld"
 "github.com/maestroi/Fleetguard/internal/safety"
 "github.com/maestroi/Fleetguard/pkg/protocol"
)

const (
 maxAgentConfigBytes=64<<10
 maxKeysBytes=32<<10
 labAcknowledgement="disposable-vm-console-ready"
)
type RuntimeConfig struct {
 NodeID string `json:"node_id"`
 ServiceGroup string `json:"service_group"`
 Mode string `json:"mode"`
 FirewallBackend string `json:"firewall_backend"`
 ControllerURL string `json:"controller_url"`
 TLSCAFile string `json:"tls_ca_file"`
 TokenFile string `json:"token_file"`
 TrustedKeysFile string `json:"trusted_keys_file"`
 SafetyPolicyFile string `json:"safety_policy_file"`
 StateDir string `json:"state_dir"`
 PollIntervalSeconds int `json:"poll_interval_seconds"`
 ReconcileIntervalSeconds int `json:"reconcile_interval_seconds"`
 MaxOfflineAgeSeconds int `json:"max_offline_age_seconds"`
 Zone string `json:"zone,omitempty"`
 Bindings []firewalld.Binding `json:"bindings,omitempty"`
 HostINPUTVerified bool `json:"host_input_verified,omitempty"`
 LabConfirm string `json:"lab_confirm,omitempty"`
}
func (c RuntimeConfig) Validate() error {
 if c.NodeID=="" || c.ServiceGroup=="" || strings.ContainsAny(c.NodeID+c.ServiceGroup," /\\?&\x00") {return errors.New("node_id and service_group must be explicit simple identifiers")}
 if c.Mode!="observe" && c.Mode!="enforce" {return errors.New("runtime mode must be observe or enforce")}
 if c.PollIntervalSeconds<1 || c.PollIntervalSeconds>60 || c.ReconcileIntervalSeconds<1 || c.ReconcileIntervalSeconds>10 {return errors.New("poll interval 1-60 and reconcile interval 1-10 seconds required")}
 if c.MaxOfflineAgeSeconds<1 || c.MaxOfflineAgeSeconds>int(protocol.MaxSnapshotTTL/time.Second) {return errors.New("offline age must be 1-300 seconds")}
 parsed,err:=url.Parse(c.ControllerURL)
 if err!=nil || parsed.Scheme!="https" || parsed.Host=="" || (parsed.Path!="" && parsed.Path!="/") || parsed.User!=nil || parsed.RawQuery!="" || parsed.Fragment!="" {
  return errors.New("controller must be an HTTPS base URL without credentials, path or query")
 }
 host:=parsed.Hostname()
 addr,err:=netip.ParseAddr(host)
 if err!=nil || (!addr.IsPrivate() && !addr.IsLoopback() && !netip.MustParsePrefix("100.64.0.0/10").Contains(addr)) || addr.IsUnspecified() || addr.Is4In6() {
  return errors.New("controller must use explicit private/loopback/Tailscale IP (not a public hostname)")
 }
 if parsed.Port()=="" {return errors.New("controller URL requires explicit port")}
 for _,name:=range []string{c.TLSCAFile,c.TokenFile,c.TrustedKeysFile,c.SafetyPolicyFile,c.StateDir} {
  if !filepath.IsAbs(name) || filepath.Clean(name)!=name {return errors.New("TLS, token, signing keys, safety and state paths must be absolute and clean")}
 }
 if c.Mode=="observe" {
  if c.FirewallBackend!="simulated" || c.HostINPUTVerified || len(c.Bindings)!=0 || c.Zone!="" || c.LabConfirm!="" {return errors.New("observe mode must use simulated backend without live-firewall options")}
 } else {
  if c.FirewallBackend!="firewalld" || !c.HostINPUTVerified || c.LabConfirm!=labAcknowledgement || len(c.Bindings)==0 || c.Zone=="" {
   return errors.New("firewalld enforcement requires explicit disposable VM confirmation, zone, bindings and INPUT attestation")
  }
 }
 return nil
}
func LoadRuntimeConfig(path string) (RuntimeConfig,error) {
 var c RuntimeConfig
 data,err:=os.ReadFile(path)
 if err!=nil{return c,err}
 if len(data)>maxAgentConfigBytes{return c,errors.New("runtime config too large")}
 decoder:=json.NewDecoder(bytes.NewReader(data))
 decoder.DisallowUnknownFields()
 if err:=decoder.Decode(&c);err!=nil{return RuntimeConfig{},err}
 var extra any
 if err:=decoder.Decode(&extra);err!=io.EOF{return RuntimeConfig{},errors.New("runtime config has trailing JSON")}
 return c,c.Validate()
}
func LoadKeys(path string,requireRoot bool)(map[string]ed25519.PublicKey,error) {
 if requireRoot {if err:=safety.CheckRootOwnedFile(path);err!=nil{return nil,err}}
 data,err:=os.ReadFile(path);if err!=nil{return nil,err}
 if len(data)>maxKeysBytes{return nil,errors.New("signer list is too large")}
 var raw map[string]string
 d:=json.NewDecoder(bytes.NewReader(data));d.DisallowUnknownFields()
 if err:=d.Decode(&raw);err!=nil{return nil,err}
 var extra any;if err:=d.Decode(&extra);err!=io.EOF{return nil,errors.New("extra trusted signer JSON")}
 if len(raw)==0 || len(raw)>16{return nil,errors.New("expected 1-16 locally trusted signing keys")}
 out:=make(map[string]ed25519.PublicKey,len(raw))
 for id,encoded:=range raw {
  if len(id)==0 || len(id)>128 || strings.ContainsAny(id," /\\?&\x00") {return nil,fmt.Errorf("invalid key ID %q",id)}
  b,err:=base64.StdEncoding.Strict().DecodeString(encoded)
  if err!=nil || len(b)!=ed25519.PublicKeySize {return nil,fmt.Errorf("invalid public Ed25519 key %q",id)}
  out[id]=ed25519.PublicKey(b)
 }
 return out,nil
}
func LoadToken(path string,requireRoot bool)(string,error) {
 if requireRoot {if err:=safety.CheckRootOwnedFile(path);err!=nil{return "",err}}
 info,err:=os.Lstat(path);if err!=nil{return "",err}
 if !info.Mode().IsRegular() || info.Mode().Perm()&0077!=0 {return "",errors.New("token file must be private and regular")}
 data,err:=os.ReadFile(path);if err!=nil{return "",err}
 if len(data)>258{return "",errors.New("token exceeds limit")}
 token:=strings.TrimSuffix(string(data),"\n")
 if len(token)<32 || len(token)>256 || strings.ContainsAny(token," \n\r\t") {return "",errors.New("token must be 32-256 bytes without whitespace")}
 return token,nil
}
func (c RuntimeConfig) LoadPolicy()(safety.Policy,error) {
 if c.Mode=="enforce" {return safety.LoadRootOwned(c.SafetyPolicyFile)}
 data,err:=os.ReadFile(c.SafetyPolicyFile)
 if err!=nil{return safety.Policy{},err}
 return safety.Parse(data)
}
