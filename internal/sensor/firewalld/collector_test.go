package firewalld

import (
 "bytes"
 "context"
 "errors"
 "fmt"
 "strings"
 "testing"
 "time"

 "github.com/maestroi/Fleetguard/pkg/protocol"
)
func settings() Config {
 return Config{
  Enabled:true,WindowSeconds:10,MaxSources:16,MaxPacketsPerWindow:100,
  MaxReportsPerWindow:8,
  Bindings:[]Binding{
   {Service:"solana-rpc",Transport:protocol.TransportTCP,Port:8899},
   {Service:"solana-rpc",Transport:protocol.TransportTCP,Port:8900},
   {Service:"ntp",Transport:protocol.TransportUDP,Port:123},
  },
 }
}
func TestBoundedAggregatorAndUnverifiedEvidence(t *testing.T){
 c,err:=NewCollector("node-a",settings());if err!=nil{t.Fatal(err)}
 now:=time.Date(2026,11,22,13,0,0,0,time.UTC)
 for i:=0;i<3000;i++{
  ip:=fmt.Sprintf("198.18.%d.%d",i/256,i%256)
  line:=fmt.Sprintf("FINAL_REJECT: IN=eth0 OUT= SRC=%s DST=192.0.2.1 PROTO=TCP DPT=8899",ip)
  c.ObserveLine(line,now)
 }
 stats:=c.Stats()
 if stats.ActiveSources>16 || stats.DroppedSources==0 || stats.Parsed!=3000 {t.Fatalf("unbounded/high-cardinality aggregation: %+v",stats)}
 out:=c.Flush(now.Add(10*time.Second))
 if len(out)>8 || len(out)==0{t.Fatalf("incorrect report cap %d",len(out))}
 ids:=map[string]bool{}
 for _,e:=range out{
  if e.ProofLevel!=protocol.ProofUnverifiedLog || e.Attempts>100 || e.NodeID!="node-a" || e.Observation!="firewalld_denied_packets"{
   t.Fatalf("bad proof, cap or node in %+v",e)
  }
  if err:=protocol.ValidateEvidence(e,"node-a",now.Add(10*time.Second));err!=nil{t.Fatalf("failed protocol v1: %v",err)}
  if ids[e.EventID] || e.EventID!=e.DedupKey{t.Fatal("duplicate IDs")}
  ids[e.EventID]=true
 }
 if c.Stats().ActiveSources!=0 {t.Fatal("unbounded retention after flush")}
 second:=c.Flush(now.Add(20*time.Second))
 if len(second)!=0{t.Fatal("replayed prior window")}
}
func TestPortDedupSortedScopeAndRateCap(t *testing.T) {
 c,err:=NewCollector("node-a",settings());if err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 c.ObserveLine("FINAL_DROP: IN=eth0 OUT= SRC=203.0.113.22 DST=192.0.2.1 PROTO=TCP DPT=8900",now)
 c.ObserveLine("FINAL_DROP: IN=eth0 OUT= SRC=203.0.113.22 DST=192.0.2.1 PROTO=TCP DPT=8899",now)
 c.ObserveLine("FINAL_DROP: IN=eth0 OUT= SRC=203.0.113.22 DST=192.0.2.1 PROTO=TCP DPT=8900",now)
 c.ObserveLine("FINAL_DROP: IN=eth0 OUT= SRC=203.0.113.22 DST=192.0.2.1 PROTO=UDP DPT=123",now)
 c.ObserveLine("FINAL_DROP: IN=eth0 OUT= SRC=203.0.113.22 DST=192.0.2.1 PROTO=TCP DPT=9999",now)
 reports:=c.Flush(now.Add(10*time.Second))
 if len(reports)!=2{t.Fatalf("expected separate TCP and UDP summaries: %+v",reports)}
 if reports[0].Service!="solana-rpc" || reports[0].Attempts!=3 || len(reports[0].DestinationPorts)!=2 || reports[0].DestinationPorts[0]!=8899 || reports[0].DestinationPorts[1]!=8900 {
  t.Fatalf("incorrect summary %+v",reports[0])
 }
 if reports[1].Service!="ntp" || reports[1].Transport!=protocol.TransportUDP{t.Fatalf("incorrect UDP summary %+v",reports[1])}
 if c.Stats().Unmapped!=1{t.Fatal("unmapped ports should not be reported")}
}
func TestPacketsPerWindowAndInvalidFrames(t *testing.T){
 cfg:=settings();cfg.MaxPacketsPerWindow=1
 c,err:=NewCollector("node-a",cfg);if err!=nil{t.Fatal(err)}
 now:=time.Now()
 c.ObserveLine(logTCP,now)
 c.ObserveLine(logTCP,now)
 c.ObserveLine("not a firewall event",now)
 c.ObserveLine("FINAL_REJECT: IN=eth0 OUT= SRC=bad DST=192.0.2.3 PROTO=TCP DPT=8899",now)
 c.NoteOversized()
 s:=c.Stats()
 if s.DroppedPackets!=1 || s.Ignored!=1 || s.Malformed!=1 || s.Oversized!=1 || s.LinesTotal!=5{t.Fatalf("incorrect metrics %+v",s)}
}
func TestScannerOversizedLineContinues(t *testing.T){
 c,err:=NewCollector("node-a",settings());if err!=nil{t.Fatal(err)}
 data:=strings.Repeat("x",MaxLineBytes*4)+"\n"+logTCP+"\n"+logUDP
 ctx:=context.Background()
 err=ScanLines(ctx,bytes.NewBufferString(data),func(line string){c.ObserveLine(line,time.Now())},c.NoteOversized)
 if err!=nil{t.Fatal(err)}
 s:=c.Stats()
 if s.Oversized!=1 || s.Parsed!=2 || s.LinesTotal!=3 {t.Fatalf("scanner lost valid lines after oversized: %+v",s)}
}
func TestConfigValidation(t *testing.T){
 cfg:=settings()
 if err:=cfg.Validate();err!=nil{t.Fatal(err)}
 cfg.Bindings=append(cfg.Bindings,cfg.Bindings[0])
 if err:=cfg.Validate();err==nil{t.Fatal("duplicate service binding accepted")}
 cfg=settings();cfg.MaxSources=999999
 if err:=cfg.Validate();err==nil{t.Fatal("unbounded sources accepted")}
 cfg=settings();cfg.Enabled=false
 if err:=cfg.Validate();err==nil{t.Fatal("disabled sensor config accepted")}
 cfg=settings();cfg.Bindings[0].Service="invalid/name"
 if err:=cfg.Validate();err==nil{t.Fatal("invalid service name accepted")}
}
func TestScannerCancellation(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 err:=ScanLines(ctx,bytes.NewBufferString(logTCP),func(string){t.Fatal("read despite cancellation")},func(){})
 if !errors.Is(err,context.Canceled){t.Fatalf("cancellation ignored: %v",err)}
}
func BenchmarkCardinalityCapped(b *testing.B){
 cfg:=settings();cfg.MaxSources=128;cfg.MaxPacketsPerWindow=100000;cfg.MaxReportsPerWindow=64
 c,err:=NewCollector("bench-a",cfg);if err!=nil{b.Fatal(err)}
 lines:=make([]string,10000)
 for i:=range lines{
  lines[i]=fmt.Sprintf("FINAL_REJECT: IN=ens18 OUT= SRC=198.18.%d.%d DST=192.0.2.2 PROTO=TCP DPT=8899",i/256,i%256)
 }
 now:=time.Now()
 b.ReportAllocs();b.ResetTimer()
 for i:=0;i<b.N;i++{
  for _,line:=range lines{c.ObserveLine(line,now)}
  if c.Stats().ActiveSources>cfg.MaxSources{b.Fatal("bounded memory invariant broken")}
  c.Flush(now.Add(time.Duration(i+1)*10*time.Second))
  now=now.Add(10*time.Second)
 }
}
