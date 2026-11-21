package agent

import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "reflect"
 "slices"
 "sync"
 "time"

 "github.com/maestroi/Fleetguard/internal/firewall"
 "github.com/maestroi/Fleetguard/internal/safety"
 "github.com/maestroi/Fleetguard/pkg/protocol"
)

// Engine is the sole owner of the monotonic revision and effective decisions.
// Poller performs transport I/O; no server response can bypass this gate.
type Engine struct {
 mu sync.Mutex
 options EngineOptions
 persisted DurableState
 snapshot *protocol.Snapshot
 local map[string]protocol.Decision
 status Status
}
type EngineOptions struct {
 Audience protocol.Audience
 Keys map[string]ed25519.PublicKey
 Policy safety.Policy
 Backend firewall.Backend
 Store Store
 Mode string // observe (simulated only) or enforce (real only)
 BackendName string
 HostINPUTVerified bool
 EmergencyDisabled func()(bool,error)
 MaxOfflineAge time.Duration
 Now func()time.Time
 // ManagementPrefixLookup overrides only in rootless tests.
 ManagementPrefixLookup safety.Runtime
}
type Status struct {
 Mode string `json:"mode"`
 Revision uint64 `json:"revision"`
 LastAppliedRevision uint64 `json:"last_applied_revision"`
 ActiveDecisions int `json:"active_decisions"`
 LocallyJustified int `json:"locally_justified"`
 OfflineExpired bool `json:"offline_expired"`
 Disabled bool `json:"emergency_disabled"`
 LastContact time.Time `json:"last_contact,omitempty"`
 LastReconcile time.Time `json:"last_reconcile,omitempty"`
 LastError string `json:"last_error,omitempty"`
 Simulated bool `json:"simulated"`
}
const DefaultMaxOfflineAge=5*time.Minute

func NewEngine(o EngineOptions) (*Engine,error) {
 if o.Now==nil {o.Now=time.Now}
 if o.Store==nil || o.Backend==nil || len(o.Keys)==0 {return nil,errors.New("agent: store, backend and public signing keys required")}
 if err:=o.Policy.Validate();err!=nil{return nil,err}
 if o.Audience.NodeID=="" || o.Audience.ServiceGroup=="" {return nil,errors.New("agent: explicit audience required")}
 if o.MaxOfflineAge==0 {o.MaxOfflineAge=DefaultMaxOfflineAge}
 if o.MaxOfflineAge<time.Second || o.MaxOfflineAge>protocol.MaxSnapshotTTL {return nil,errors.New("agent: offline age must be 1-300 seconds")}
 if o.Mode!="observe" && o.Mode!="enforce" {return nil,errors.New("agent: explicit mode required")}
 if o.Mode=="enforce" && (o.Policy.Mode!="enforce" || o.BackendName!="firewalld" || !o.HostINPUTVerified || o.EmergencyDisabled==nil) {
  return nil,errors.New("agent: enforcement requires locally verified firewalld, enforce policy and emergency latch")
 }
 if o.Mode=="observe" && o.BackendName!="simulated" {return nil,errors.New("agent: observe mode requires simulated backend")}
 for id,key:=range o.Keys {if id=="" || len(key)!=ed25519.PublicKeySize {return nil,fmt.Errorf("invalid trusted key %q",id)}}
 state,err:=o.Store.Load();if err!=nil{return nil,fmt.Errorf("load persisted policy: %w",err)}
 e:=&Engine{options:o,persisted:state,local:make(map[string]protocol.Decision),status:Status{Mode:o.Mode,Revision:state.Revision,Simulated:o.Mode=="observe"}}
 if state.Revision==0 {return e,nil}
 now:=o.Now()
 if state.AcceptedAt.After(now.Add(protocol.MaxClockSkew)) {return nil,errors.New("stored acceptance timestamp in the future; refusing clock rollback")}
 // Re-verify at original acceptance time so individual decisions that have
 // since expired do not invalidate other, still-live signed decisions.
 // The original acceptance time is trusted only from the private state file.
 snap,err:=protocol.VerifySignedSnapshot(*state.Signed,o.Keys,o.Audience,state.Revision-1,state.AcceptedAt)
 if err!=nil{return nil,fmt.Errorf("stored signature/identity/revision invalid: %w",err)}
 if snap.Revision!=state.Revision {return nil,errors.New("persisted watermark disagrees with signed revision")}
 if snap.ExpiresAt.After(now) && state.AcceptedAt.Add(o.MaxOfflineAge).After(now) {
  live:=prune(snap.Decisions,now)
  candidate:=snap;candidate.Decisions=live
  if err:=o.Policy.CheckCandidate(candidate,o.Audience,now,o.ManagementPrefixLookup);err!=nil{
   return nil,fmt.Errorf("restored desired state violates local safety: %w",err)
  }
  e.snapshot=&snap
 } else {
  e.status.OfflineExpired=true
 }
 return e,nil
}
func prune(in []protocol.Decision,now time.Time) []protocol.Decision {
 out:=make([]protocol.Decision,0,len(in))
 for _,d:=range in {if d.ExpiresAt.After(now) {d.DestinationPorts=append([]uint16(nil),d.DestinationPorts...);out=append(out,d)}}
 return out
}
func ack(o EngineOptions,revision uint64,state protocol.DecisionState,reason protocol.ReasonCode) protocol.Acknowledgement {
 return protocol.Acknowledgement{Schema:protocol.SchemaVersion,NodeID:o.Audience.NodeID,Revision:revision,State:state,Reason:reason}
}
func (e *Engine) Status() Status {
 e.mu.Lock();defer e.mu.Unlock()
 return e.status
}
func (e *Engine) setError(err error) {
 if err!=nil {e.status.LastError=err.Error()} else {e.status.LastError=""}
}
func (e *Engine) MarkContact() {
 e.mu.Lock();defer e.mu.Unlock()
 e.status.LastContact=e.options.Now()
}

// Accept verifies the exact Ed25519 bytes and local protections BEFORE
// atomically persisting the new revision. The effective backend state is
// reconciled only after successful persistence. Persist-before-apply means a
// crash cannot apply an unrecorded revision or reaccept an older revision.
func (e *Engine) Accept(ctx context.Context,envelope protocol.SignedSnapshot)(protocol.Acknowledgement,error) {
 e.mu.Lock();defer e.mu.Unlock()
 if err:=ctx.Err();err!=nil{return protocol.Acknowledgement{},err}
 now:=e.options.Now()
 if e.persisted.Revision>0 && e.persisted.Signed!=nil && reflect.DeepEqual(envelope,*e.persisted.Signed) {
  // Controller repeats an identical signed snapshot until expiry. This is
  // idempotent polling, not acceptance of an unrelated same-revision replay.
  if e.snapshot==nil || !e.snapshot.ExpiresAt.After(now) || !e.persisted.AcceptedAt.Add(e.options.MaxOfflineAge).After(now) {
   err:=errors.New("previous signed snapshot has expired")
   e.setError(err);return protocol.Acknowledgement{},err
  }
  if err:=e.reconcile(ctx);err!=nil{return ack(e.options,e.persisted.Revision,protocol.StateError,protocol.ReasonInvalidDecision),err}
  return e.appliedAck(),nil
 }
 signed,err:=protocol.VerifySignedSnapshot(envelope,e.options.Keys,e.options.Audience,e.persisted.Revision,now)
 if err!=nil {e.setError(err);return protocol.Acknowledgement{},err}
 if err:=e.options.Policy.CheckCandidate(signed,e.options.Audience,now,e.options.ManagementPrefixLookup);err!=nil {
  e.setError(err);return ack(e.options,signed.Revision,protocol.StateRejected,protocol.ReasonScopeMismatch),err
 }
 if e.options.Mode=="enforce" {
  disabled,err:=e.options.EmergencyDisabled()
  if err!=nil || disabled {if err==nil {err=errors.New("local emergency kill switch active")};e.setError(err);return ack(e.options,signed.Revision,protocol.StateRejected,protocol.ReasonScopeMismatch),err}
  capabilities,err:=e.options.Backend.Capabilities(ctx)
  if err!=nil {e.setError(err);return ack(e.options,signed.Revision,protocol.StateError,protocol.ReasonInvalidDecision),err}
  runtime:=e.options.ManagementPrefixLookup
  runtime.BackendName=e.options.BackendName;runtime.Verified=e.options.HostINPUTVerified;runtime.Capabilities=capabilities
  if err:=e.options.Policy.Authorize(signed,e.options.Audience,now,runtime);err!=nil {
   e.setError(err);return ack(e.options,signed.Revision,protocol.StateRejected,protocol.ReasonScopeMismatch),err
  }
 }
 next:=DurableState{Version:1,Revision:signed.Revision,Signed:&envelope,AcceptedAt:now}
 if err:=e.options.Store.Save(next);err!=nil {e.setError(err);return ack(e.options,signed.Revision,protocol.StateError,protocol.ReasonMalformed),err}
 e.persisted=next
 e.snapshot=&signed
 e.status.Revision=signed.Revision
 e.status.OfflineExpired=false
 if err:=e.reconcile(ctx);err!=nil{return ack(e.options,signed.Revision,protocol.StateError,protocol.ReasonInvalidDecision),err}
 return e.appliedAck(),nil
}
func (e *Engine) appliedAck() protocol.Acknowledgement {
 state:=protocol.StateValidated
 if e.options.Mode=="enforce" {state=protocol.StateApplied}
 return ack(e.options,e.persisted.Revision,state,"")
}
// Tick can run without controller connectivity. It prunes expired entries,
// checks emergency latch every time, and repairs firewalld runtime reload
// drift by reconciling desired state against freshly inspected D-Bus state.
func (e *Engine) Tick(ctx context.Context) error {
 e.mu.Lock();defer e.mu.Unlock()
 return e.reconcile(ctx)
}
func (e *Engine) reconcile(ctx context.Context) error {
 if err:=ctx.Err();err!=nil{e.setError(err);return err}
 now:=e.options.Now()
 desired:=make([]protocol.Decision,0)
 valid:=e.snapshot!=nil && e.snapshot.ExpiresAt.After(now) && e.persisted.AcceptedAt.Add(e.options.MaxOfflineAge).After(now)
 if valid {desired=append(desired,prune(e.snapshot.Decisions,now)...)} else if e.persisted.Revision>0 {e.status.OfflineExpired=true}
 for id,d:=range e.local {
  if !d.ExpiresAt.After(now) {delete(e.local,id);continue}
  desired=append(desired,d)
 }
 if e.options.Mode=="enforce" {
  disabled,err:=e.options.EmergencyDisabled()
  if err!=nil || disabled {
   e.status.Disabled=true
   if errRemove:=e.options.Backend.RemoveOwned(ctx);errRemove!=nil{e.setError(errRemove);return fmt.Errorf("emergency removal failed: %w",errRemove)}
   e.status.ActiveDecisions=0
   e.status.LastReconcile=now
   if err!=nil {e.setError(err);return err}
   e.setError(nil);return nil
  }
  e.status.Disabled=false
  caps,err:=e.options.Backend.Capabilities(ctx)
  if err!=nil{e.setError(err);return err}
  runtime:=e.options.ManagementPrefixLookup
  runtime.BackendName=e.options.BackendName;runtime.Verified=e.options.HostINPUTVerified;runtime.Capabilities=caps
  // Local sources have been individually approved. Validate the combined
  // effective state again after TTL pruning, before each firewall mutation.
  synthetic:=protocol.Snapshot{Schema:protocol.SchemaVersion,Revision:1,IssuedAt:now,ExpiresAt:now.Add(protocol.MaxSnapshotTTL),
   Audience:e.options.Audience,Decisions:desired,KeyID:"local-reconciled"}
  if err:=e.options.Policy.Authorize(synthetic,e.options.Audience,now,runtime);err!=nil{e.setError(err);return err}
 } else if len(desired)>e.options.Policy.MaxDecisions {
  err:=errors.New("agent: combined decision cap exceeded");e.setError(err);return err
 }
 applied,err:=e.options.Backend.Reconcile(ctx,desired)
 if err!=nil{e.setError(err);return err}
 if e.options.Mode=="enforce" && applied.Simulated {err=errors.New("real backend unexpectedly returned simulated result");e.setError(err);return err}
 e.status.ActiveDecisions=len(applied.Decisions)
 e.status.LocallyJustified=len(e.local)
 e.status.LastReconcile=now
 if valid {e.status.LastAppliedRevision=e.persisted.Revision}
 e.setError(nil)
 return nil
}
// AddLocal accepts only short-lived, independently justified local decisions.
// Unverified log-only/UDP packet observations cannot trigger bans. They are
// deliberately not persisted; crashes clear them instead of recreating an
// unverified local decision after a restart.
func (e *Engine) AddLocal(ctx context.Context,d protocol.Decision,proof protocol.ProofLevel) error {
 e.mu.Lock();defer e.mu.Unlock()
 if e.options.Mode!="enforce" {return errors.New("local bans require explicit enforcement mode")}
 if proof!=protocol.ProofApplicationVerified && !(proof==protocol.ProofEstablishedConnection && d.Transport==protocol.TransportTCP) {
  return errors.New("log-only or unverified local evidence is not eligible for blocking")
 }
 now:=e.options.Now()
 if len(e.local)>=e.options.Policy.MaxDecisions {return errors.New("local decision limit reached")}
 d.ID="local-"+d.ID
 if _,ok:=e.local[d.ID];ok{return errors.New("duplicate local decision ID")}
 synthetic:=protocol.Snapshot{Schema:protocol.SchemaVersion,Revision:1,IssuedAt:now,ExpiresAt:now.Add(protocol.MaxSnapshotTTL),
  Audience:e.options.Audience,Decisions:[]protocol.Decision{d},KeyID:"local-reconciled"}
 if err:=e.options.Policy.CheckCandidate(synthetic,e.options.Audience,now,e.options.ManagementPrefixLookup);err!=nil{return err}
 if disabled,err:=e.options.EmergencyDisabled();err!=nil{return err}else if disabled{return errors.New("emergency disabled")}
 e.local[d.ID]=d
 if err:=e.reconcile(ctx);err!=nil{delete(e.local,d.ID);return err}
 return nil
}
func (e *Engine) PendingLocalIDs() []string {
 e.mu.Lock();defer e.mu.Unlock()
 out:=make([]string,0,len(e.local));for id:=range e.local{out=append(out,id)}
 slices.Sort(out)
 return out
}
