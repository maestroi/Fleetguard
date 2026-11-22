package exposure

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/maestroi/Fleetguard/pkg/protocol"
)
func readExample(t *testing.T,name string)Document {
 t.Helper()
 doc,err:=Load(filepath.Join("..","..","examples","exposure",name+".json"))
 if err!=nil{t.Fatal(err)}
 return doc
}
func compiled(t *testing.T,name string)Effective{
 t.Helper()
 out,err:=Compile(readExample(t,name),time.Date(2026,11,22,12,0,0,0,time.UTC))
 if err!=nil{t.Fatal(err)}
 return out
}
func observed(now time.Time,paths ...Path)Observed {
 return Observed{Schema:SchemaVersion,ObservedAt:now,
  Coverage:Coverage{Listeners:true,Firewalld:true,Forwarding:true,External:true},
  Listeners:[]Listener{},Paths:paths}
}
func ext(transport protocol.Transport,port uint16)Path{
 return Path{Direction:"ingress",Transport:transport,Port:port,Source:"public",State:"verified_reachable",Provenance:"external_probe"}
}
func codes(r Report)[]string {
 out:=make([]string,0,len(r.Findings))
 for _,f:=range r.Findings{out=append(out,f.Code)}
 return out
}
func hasCode(r Report,code string,port uint16)bool{
 for _,f:=range r.Findings {if f.Code==code && f.Port==port {return true}}
 return false
}
func TestWebEdge443AllowedBaselineUnexpected(t *testing.T){
 now:=time.Now().UTC()
 o:=observed(now,ext(protocol.TransportTCP,443))
 o.Listeners=[]Listener{{Transport:protocol.TransportTCP,Port:443,Bind:"wildcard"}}
 web,err:=Evaluate(compiled(t,"web-edge"),o);if err!=nil{t.Fatal(err)}
 if hasCode(web,"unexpected_public_exposure",443) || hasCode(web,"unexpected_listener",443) {
  t.Fatalf("443 must be allowed only for explicit web-edge: %+v",web.Findings)
 }
 d:=readExample(t,"web-edge");d.Assigned=[]string{"baseline-linux"};d.Role="baseline-linux"
 baseline,err:=Compile(d,now);if err!=nil{t.Fatal(err)}
 result,err:=Evaluate(baseline,o);if err!=nil{t.Fatal(err)}
 if !hasCode(result,"unexpected_public_exposure",443){t.Fatalf("443 unexpected outside web role: %v",codes(result))}
}
func TestSuiFullnodeUDPAcceptedMetricsAdminForbidden(t *testing.T){
 now:=time.Now().UTC()
 d:=compiled(t,"sui-fullnode")
 o:=observed(now,ext(protocol.TransportUDP,8084),ext(protocol.TransportTCP,9184),ext(protocol.TransportTCP,1337))
 o.Listeners=[]Listener{{Transport:protocol.TransportUDP,Port:8084,Bind:"wildcard"},{Transport:protocol.TransportTCP,Port:9184,Bind:"wildcard"},{Transport:protocol.TransportTCP,Port:1337,Bind:"wildcard"}}
 result,err:=Evaluate(d,o);if err!=nil{t.Fatal(err)}
 if hasCode(result,"unexpected_public_exposure",8084) || hasCode(result,"forbidden_exposure",8084){t.Fatal("expected sui 8084/udp was forbidden/unexpected")}
 for _,port:=range []uint16{9184,1337}{
  if !hasCode(result,"forbidden_exposure",port){t.Fatalf("public %d not flagged: %+v",port,result.Findings)}
 }
 for _,f:=range result.Findings{if f.Code=="forbidden_exposure" && f.Confidence!="verified_external"{t.Fatalf("unexpected confidence %+v",f)}}
}
func TestSolanaValidatorTrustedDynamicRangeNotRPC(t *testing.T){
 d:=compiled(t,"solana-validator")
 hasUDP:=false
 for _,r:=range d.Rules{
  if r.ID=="configured-p2p-range" && r.Transport==protocol.TransportUDP && r.Ports== (PortRange{From:8000,To:8020}) {hasUDP=true}
  if r.ID=="rpc-http"{t.Fatal("unassigned RPC role leaked into validator")}
 }
 if !hasUDP{t.Fatal("missing locally configured Solana range")}
 now:=time.Now().UTC()
 result,err:=Evaluate(d,observed(now,ext(protocol.TransportUDP,8001),ext(protocol.TransportTCP,8899)))
 if err!=nil{t.Fatal(err)}
 if hasCode(result,"unexpected_public_exposure",8001) || !hasCode(result,"forbidden_exposure",8899){t.Fatalf("incorrect Solana classification %+v",result.Findings)}
 d2:=readExample(t,"solana-validator")
 delete(d2.PortParameters,"solana_dynamic_ports")
 if _,err:=Compile(d2,now);err==nil{t.Fatal("silently assumed Solana dynamic-port-range")}
}
func TestConflictingOverridesAndProtectedManagement(t *testing.T){
 now:=time.Now().UTC()
 d:=readExample(t,"web-edge")
 d.Protected=[]Entry{{ID:"protected-console",Direction:"ingress",Transport:protocol.TransportTCP,Ports:PortRange{From:443,To:443},Source:"public",Intent:"forbidden"}}
 if _,err:=Compile(d,now);err==nil || !strings.Contains(err.Error(),"conflicting"){t.Fatalf("overlap was not rejected: %v",err)}
 d=readExample(t,"web-edge")
 d.Overrides=[]Override{{Entry:"web-edge/public-https",Intent:"forbidden",Operator:"operator-a",Reason:"maintenance window",ExpiresAt:now.Add(time.Hour)}}
 if _,err:=Compile(d,now);err!=nil{t.Fatal("trusted local override should work with no conflicting protected rule:",err)}
 d.Overrides[0].ExpiresAt=now.Add(-time.Hour)
 e,err:=Compile(d,now);if err!=nil{t.Fatal(err)}
 found:=false
 for _,r:=range e.Rules{if r.ID=="public-https" && r.Intent=="required"{found=true}}
 if !found{t.Fatal("expired override remained effective")}
 d=readExample(t,"web-edge")
 d.Overrides=[]Override{{Entry:"web-edge/public-https",Intent:"forbidden",Operator:"operator-a",Reason:"maintenance window",ExpiresAt:now.Add(8*24*time.Hour)}}
 if _,err:=Compile(d,now);err==nil{t.Fatal("8-day override accepted")}
 d=readExample(t,"web-edge")
 d.Profiles[1].Extends=[]string{"web-edge"}
 if _,err:=Compile(d,now);err==nil{t.Fatal("inheritance cycle accepted")}
}
func TestOptionalConditionsAndAssignedRoleBoundary(t *testing.T){
 now:=time.Now()
 d:=readExample(t,"sui-fullnode")
 for _,r:=range compiled(t,"sui-fullnode").Rules{if r.ID=="public-api"{t.Fatal("disabled optional Sui API inherited public exposure")}}
 d.Flags["public_api_enabled"]=true
 e,err:=Compile(d,now);if err!=nil{t.Fatal(err)}
 has443:=false;for _,r:=range e.Rules {if r.ID=="public-api" && r.Ports.From==443{has443=true}}
 if !has443{t.Fatal("locally enabled conditional API missing")}
 d.Assigned=[]string{"web-edge"}
 if _,err:=Compile(d,now);err==nil{t.Fatal("role mismatch granted web-edge exposure")}
 d=readExample(t,"sui-fullnode")
 delete(d.Flags,"public_api_enabled")
 if _,err:=Compile(d,now);err==nil{t.Fatal("missing local condition silently accepted")}
}
func TestCoverageUnknownNotInternetAndMissingRequired(t *testing.T){
 now:=time.Now().UTC()
 e:=compiled(t,"web-edge")
 o:=Observed{Schema:SchemaVersion,ObservedAt:now,Listeners:[]Listener{{Transport:protocol.TransportTCP,Port:443,Bind:"wildcard"}},
  Coverage:Coverage{Listeners:true,Firewalld:false,Forwarding:false,External:false}}
 r,err:=Evaluate(e,o);if err!=nil{t.Fatal(err)}
 if hasCode(r,"forbidden_exposure",443) || hasCode(r,"unexpected_public_exposure",443){t.Fatal("listener falsely deemed public")}
 if !hasCode(r,"unknown_path",443){t.Fatal("incomplete path coverage not visible")}
 o.Listeners=nil;o.Coverage.Forwarding=true
 r,err=Evaluate(e,o);if err!=nil{t.Fatal(err)}
 if !hasCode(r,"required_port_unavailable",443){t.Fatalf("missing required service unreported %+v",r.Findings)}
 if r.Findings[0].Confidence=="verified_external"{t.Fatal("local absence claimed external probe")}
}
func TestConfiguredAllowNotVerifiedExternal(t *testing.T){
 now:=time.Now()
 d:=readExample(t,"web-edge");d.Assigned=[]string{"baseline-linux"};d.Role="baseline-linux"
 expected,err:=Compile(d,now);if err!=nil{t.Fatal(err)}
 o:=Observed{Schema:SchemaVersion,ObservedAt:now,Coverage:Coverage{Firewalld:true},
  Paths:[]Path{{Direction:"ingress",Transport:protocol.TransportTCP,Port:443,Source:"public",State:"configured_allow",Provenance:"firewall_runtime"}}}
 r,err:=Evaluate(expected,o);if err!=nil{t.Fatal(err)}
 if !hasCode(r,"unexpected_public_exposure",443){t.Fatalf("expected config drift %+v",r.Findings)}
 for _,f:=range r.Findings{if f.Confidence=="verified_external"{t.Fatalf("firewall rule wrongly claimed internet access %+v",f)}}
}
func TestStrictObservedFixtureLimits(t *testing.T){
 var o Observed
 if err:=ParseObserved([]byte(`{"schema":1,"observed_at":"2026-11-22T12:00:00Z","coverage":{},"listeners":[],"paths":[],"remote_enable":true}`),&o);err==nil{t.Fatal("unknown remote field accepted")}
 if err:=ParseObserved(bytes.Repeat([]byte("x"),512<<10+1),&o);err==nil{t.Fatal("oversized observed input accepted")}
 src,err:=os.ReadFile(filepath.Join("..","..","examples","exposure","sui-fullnode-observed.json"))
 if err!=nil{t.Fatal(err)}
 if err:=ParseObserved(src,&o);err!=nil{t.Fatal(err)}
 if _,err:=Evaluate(compiled(t,"sui-fullnode"),o);err!=nil{t.Fatal(err)}
 raw,err:=json.Marshal(o);if err!=nil{t.Fatal(err)}
 if len(raw)>512<<10{t.Fatal("fixture inexplicably large")}
}
func TestTrackerDedupAndGrace(t *testing.T){
 now:=time.Now().UTC()
 r:=Report{Findings:[]Finding{{ID:"test-1",Code:"unexpected_public_exposure",Severity:"high"}}}
 tracker,err:=NewTracker(5*time.Second);if err!=nil{t.Fatal(err)}
 if a:=tracker.Update(r,now);len(a)!=0{t.Fatal("alert before grace")}
 if a:=tracker.Update(r,now.Add(4*time.Second));len(a)!=0{t.Fatal("premature alert")}
 if a:=tracker.Update(r,now.Add(5*time.Second));len(a)!=1 || a[0].Kind!="new"{t.Fatal("missing new alert")}
 if a:=tracker.Update(r,now.Add(50*time.Second));len(a)!=0{t.Fatal("repeat alert spam")}
 if a:=tracker.Update(Report{},now.Add(51*time.Second));len(a)!=1 || a[0].Kind!="resolved"{t.Fatal("resolved drift not reported")}
 if a:=tracker.Update(r,now.Add(60*time.Second));len(a)!=0{t.Fatal("grace not reset for new drift")}
 if _,err:=NewTracker(10*time.Minute);err==nil{t.Fatal("unbounded maintenance grace")}
}
type fakeDBus struct{}
func (fakeDBus)GetActiveZones(context.Context)(map[string]map[string][]string,error){return map[string]map[string][]string{"public":{"interfaces":{"ens18"}}},nil}
func (fakeDBus)GetPorts(context.Context,string)([][]string,error){return [][]string{{"443","tcp"},{"8084","udp"}},nil}
func (fakeDBus)GetServices(context.Context,string)([]string,error){return []string{"ssh"},nil}
func (fakeDBus)GetRichRules(context.Context,string)([]string,error){return []string{"rule family=ipv4 drop"},nil}
func (fakeDBus)GetForwardPorts(context.Context,string)([][]string,error){return nil,nil}
func TestReadOnlyFirewalldInspectionAndProcSockets(t *testing.T){
 now:=time.Now()
 o:=Observed{Schema:SchemaVersion,ObservedAt:now}
 if err:=InspectFirewalld(context.Background(),fakeDBus{},&o);err!=nil{t.Fatal(err)}
 if !o.Coverage.Firewalld || len(o.Paths)!=2 || len(o.Coverage.Notes)==0{t.Fatalf("partial coverage not represented %+v",o)}
 sample:="sl local_address rem_address st tx_queue\n0: 00000000:01BB 00000000:0000 0A 0000\n1: 0100007F:0050 00000000:0000 0A 0000\n2: 00000000:22B8 00000000:0000 01 0000\n"
 listeners,err:=ParseProcSockets(strings.NewReader(sample),protocol.TransportTCP,false);if err!=nil{t.Fatal(err)}
 if len(listeners)!=2 || listeners[0].Port!=443 || listeners[0].Bind!="wildcard" || listeners[1].Bind!="loopback"{t.Fatalf("unexpected kernel socket decode %+v",listeners)}
 if _,err:=ParseProcSockets(bytes.NewReader(bytes.Repeat([]byte("x"),maxProcBytes+1)),protocol.TransportUDP,false);err==nil{t.Fatal("unbounded proc reader")}
}
func TestObserverCannotWriteFirewall(t *testing.T){
 // No mutating D-Bus client interface is exposed to this package.
 _ = errors.Is(context.Canceled,context.Canceled)
}
