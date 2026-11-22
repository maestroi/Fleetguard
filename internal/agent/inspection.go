package agent

import (
 "context"
 "errors"
 "fmt"
 "net/netip"
 "sort"
 "time"

 "github.com/maestroi/Fleetguard/internal/safety"
 "github.com/maestroi/Fleetguard/pkg/protocol"
)

type DecisionView struct {
 protocol.Decision
 RemainingSeconds int64 `json:"remaining_seconds"`
 Origin string `json:"origin"`
}

type Inspection struct {
 Schema int `json:"schema"`
 ObservedAt time.Time `json:"observed_at"`
 NodeID string `json:"node_id"`
 ServiceGroup string `json:"service_group"`
 Mode string `json:"mode"`
 Revision uint64 `json:"revision"`
 SignerKeyID string `json:"signer_key_id,omitempty"`
 SignedIssuedAt *time.Time `json:"signed_issued_at,omitempty"`
 SignedExpiresAt *time.Time `json:"signed_expires_at,omitempty"`
 AcceptedAt *time.Time `json:"accepted_at,omitempty"`
 Acceptance string `json:"acceptance"`
 Enforcement string `json:"enforcement"`
 KernelVerified bool `json:"kernel_verified"`
 KernelObservedAt *time.Time `json:"kernel_observed_at,omitempty"`
 BackendError string `json:"backend_error,omitempty"`
 SignedDesired []DecisionView `json:"signed_desired"`
 AcceptedEffective []DecisionView `json:"accepted_effective"`
 BackendObserved []DecisionView `json:"backend_observed"`
 Simulated bool `json:"simulated"`
 EmergencyDisabled bool `json:"emergency_disabled"`
}

func InspectSource(raw string) (string,error) {
 addr,err:=netip.ParseAddr(raw)
 if err!=nil || !addr.Is4() || addr.Is4In6() || addr.IsUnspecified() || addr.IsMulticast() || addr.String()!=raw {
  return "",errors.New("inspect requires a canonical IPv4 address (not a CIDR)")
 }
 return netip.PrefixFrom(addr,32).String(),nil
}

func record(decisions []protocol.Decision,now time.Time,origin,source string)[]DecisionView {
 result:=make([]DecisionView,0,len(decisions))
 for _,d:=range decisions {
  if source!="" && d.Source!=source{continue}
  remaining:=int64(0)
  if d.ExpiresAt.After(now) {remaining=int64(d.ExpiresAt.Sub(now).Seconds());if remaining==0{remaining=1}}
  result=append(result,DecisionView{Decision:d,RemainingSeconds:remaining,Origin:origin})
 }
 sort.Slice(result,func(i,j int)bool {
  a,b:=result[i],result[j]
  if a.Source!=b.Source{return a.Source<b.Source}
  if a.Service!=b.Service{return a.Service<b.Service}
  return a.ID<b.ID
 })
 return result
}

// InspectRuntime is read-only. A saved accepted signature is reverified at
// its ORIGINAL acceptance timestamp; expired signed decisions are historical
// desired state only. The real backend is inspected, never reconciled.
func InspectRuntime(ctx context.Context,configPath,filterIP string,now time.Time)(Inspection,error){
 cfg,err:=LoadRuntimeConfig(configPath)
 if err!=nil{return Inspection{},err}
 if cfg.Mode=="enforce" {
  if err:=safety.CheckRootOwnedFile(configPath);err!=nil{return Inspection{},err}
 }
 source:=""
 if filterIP!=""{source,err=InspectSource(filterIP);if err!=nil{return Inspection{},err}}
 policy,err:=cfg.LoadPolicy();if err!=nil{return Inspection{},err}
 keys,err:=LoadKeys(cfg.TrustedKeysFile,cfg.Mode=="enforce");if err!=nil{return Inspection{},err}
 stored,err:=(FileStore{Dir:cfg.StateDir,RequireRoot:cfg.Mode=="enforce"}).Load()
 if err!=nil{return Inspection{},err}
 view:=Inspection{
  Schema:1,ObservedAt:now.UTC(),NodeID:cfg.NodeID,ServiceGroup:cfg.ServiceGroup,
  Mode:cfg.Mode,Revision:stored.Revision,Acceptance:"none",Enforcement:"unknown",
  SignedDesired:[]DecisionView{},AcceptedEffective:[]DecisionView{},BackendObserved:[]DecisionView{},
  Simulated:cfg.Mode=="observe",
 }
 if cfg.Mode=="observe"{view.Enforcement="simulated_only"}
 if stored.Revision>0 {
  if stored.Signed==nil{return Inspection{},errors.New("missing signed state")}
  if stored.AcceptedAt.After(now.Add(protocol.MaxClockSkew)){return Inspection{},errors.New("future persisted acceptance")}
  snap,err:=protocol.VerifySignedSnapshot(*stored.Signed,keys,protocol.Audience{NodeID:cfg.NodeID,ServiceGroup:cfg.ServiceGroup},stored.Revision-1,stored.AcceptedAt)
  if err!=nil{return Inspection{},fmt.Errorf("persisted signature invalid: %w",err)}
  if snap.Revision!=stored.Revision{return Inspection{},errors.New("persisted revision differs from signed revision")}
  issued,expires,accepted:=snap.IssuedAt,snap.ExpiresAt,stored.AcceptedAt
  view.SignerKeyID=snap.KeyID
  view.SignedIssuedAt=&issued;view.SignedExpiresAt=&expires;view.AcceptedAt=&accepted
  view.SignedDesired=record(snap.Decisions,now,"central_signed",source)
  if snap.ExpiresAt.After(now) && stored.AcceptedAt.Add(time.Duration(cfg.MaxOfflineAgeSeconds)*time.Second).After(now){
   candidate:=snap
   candidate.Decisions=prune(snap.Decisions,now)
   if err:=policy.CheckCandidate(candidate,protocol.Audience{NodeID:cfg.NodeID,ServiceGroup:cfg.ServiceGroup},now,safety.Runtime{});err!=nil {
    view.Acceptance="unsafe"
    view.BackendError="current local safety check failed: "+err.Error()
   } else {
    view.Acceptance="current"
    view.AcceptedEffective=record(candidate.Decisions,now,"central_accepted",source)
   }
  }else{view.Acceptance="expired"}
 }
 if cfg.Mode=="enforce" {
  disabled,err:=safety.Disabled(cfg.StateDir)
  if err!=nil {view.Enforcement="unavailable";view.BackendError=err.Error();return view,nil}
  view.EmergencyDisabled=disabled
  backend,closeBackend,err:=BuildRealBackend(cfg,policy)
  if err!=nil{view.Enforcement="unavailable";view.BackendError=err.Error();return view,nil}
  defer closeBackend()
  applied,err:=backend.Inspect(ctx)
  if err!=nil{view.Enforcement="unavailable";view.BackendError=err.Error();return view,nil}
  if applied.Simulated{return Inspection{},errors.New("real backend returned simulated state")}
  view.Enforcement="inspected"
  view.KernelVerified=true
  view.KernelObservedAt=&applied.ObservedAt
  view.BackendObserved=record(applied.Decisions,now,"unknown_backend",source)
  for i:=range view.BackendObserved {
   for _,accepted:=range view.AcceptedEffective {
    got:=view.BackendObserved[i]
    if got.ID==accepted.ID && got.Source==accepted.Source && got.Service==accepted.Service && got.Transport==accepted.Transport {
     view.BackendObserved[i].Origin="central_accepted";break
    }
   }
  }
 }
 return view,nil
}
