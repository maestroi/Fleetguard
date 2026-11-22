package agent

import (
 "context"
 "testing"

 "github.com/maestroi/Fleetguard/pkg/protocol"
)

func TestOperatorCountersNeverClaimAppliedWhenSimulated(t *testing.T){
 e,_,now,priv,_:=fixture(t,"observe")
 valid:=snapshot(t,priv,*now,1,"203.0.113.42/32")
 invalid:=valid
 invalid.SignatureBase64="invalid"
 if _,err:=e.Accept(context.Background(),invalid);err==nil{t.Fatal("bad signed snapshot accepted")}
 if e.Status().InvalidSnapshots!=1{t.Fatalf("invalid signature count: %+v",e.Status())}
 rejected:=snapshot(t,priv,*now,1,"10.7.8.9/32")
 if _,err:=e.Accept(context.Background(),rejected);err==nil{t.Fatal("protected CIDR was not rejected")}
 if e.Status().RejectedScopes!=1{t.Fatalf("rejected scope count %+v",e.Status())}
 if _,err:=e.Accept(context.Background(),valid);err!=nil{t.Fatal(err)}
 status:=e.Status()
 if status.LastAcceptedAt.IsZero() || status.CentralDecisions!=1 || status.Mode!="observe" || !status.Simulated || status.LastAppliedRevision!=1{
  t.Fatalf("incorrect agent counters/semantics: %+v",status)
 }
 if status.InvalidSnapshots!=1 || status.RejectedScopes!=1 || status.ReconcileErrors!=0{t.Fatalf("counters lost: %+v",status)}
 _=protocol.StateValidated
}
func TestFailedKernelReconcileIsCountedAndNotReportedApplied(t *testing.T){
 e,_,now,priv,fake:=fixture(t,"enforce")
 fake.fail=true
 env:=snapshot(t,priv,*now,1,"203.0.113.42/32")
 if _,err:=e.Accept(context.Background(),env);err==nil{t.Fatal("backend outage unexpectedly applied policy")}
 status:=e.Status()
 if status.ReconcileErrors!=1 || status.LastAppliedRevision!=0 || status.LastError==""{
  t.Fatalf("failed reconcile reported applied: %+v",status)
 }
}
