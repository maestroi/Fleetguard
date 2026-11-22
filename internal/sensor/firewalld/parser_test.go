package firewalld

import (
 "errors"
 "strings"
 "testing"

 "github.com/maestroi/Fleetguard/pkg/protocol"
)

const logTCP="FINAL_REJECT: IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=198.51.100.42 DST=192.0.2.3 LEN=60 PROTO=TCP SPT=44100 DPT=8899 SYN"
const logUDP="kernel: [1.234] filter_IN_public_DROP: IN=ens18 OUT= SRC=192.0.2.7 DST=198.51.100.2 LEN=78 PROTO=UDP SPT=137 DPT=137 LEN=58"
func TestParseLineFixtures(t *testing.T){
 tests:=[]struct{name,line string;kind protocol.Transport;port uint16;ignore,invalid bool}{
  {"tcp",logTCP,protocol.TransportTCP,8899,false,false},
  {"udp double len",logUDP,protocol.TransportUDP,137,false,false},
  {"zone reject","filter_IN_public_REJECT: IN=bond0 OUT= SRC=203.0.113.77 DST=10.0.0.2 PROTO=TCP SPT=7000 DPT=22 SYN",protocol.TransportTCP,22,false,false},
  {"forward","FINAL_REJECT: IN=eth0 OUT=docker0 SRC=203.0.113.1 DST=198.51.100.2 PROTO=TCP DPT=8899", "",0,true,false},
  {"non firewalld","[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.1 DST=198.51.100.2 PROTO=TCP DPT=8899","",0,true,false},
  {"custom prefix","SSH-DENIED: IN=eth0 OUT= SRC=203.0.113.1 DST=198.51.100.2 PROTO=TCP DPT=22","",0,true,false},
  {"ipv6","FINAL_REJECT: IN=eth0 OUT= SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP DPT=443","",0,false,true},
  {"missing OUT","FINAL_REJECT: IN=eth0 SRC=203.0.113.1 DST=192.0.2.1 PROTO=TCP DPT=443","",0,false,true},
  {"loopback","FINAL_REJECT: IN=lo OUT= SRC=127.0.0.1 DST=192.0.2.1 PROTO=TCP DPT=443","",0,false,true},
  {"duplicate SRC","FINAL_REJECT: IN=eth0 OUT= SRC=203.0.113.1 SRC=203.0.113.2 DST=192.0.2.1 PROTO=TCP DPT=443","",0,false,true},
  {"invalid port","FINAL_REJECT: IN=eth0 OUT= SRC=203.0.113.1 DST=192.0.2.1 PROTO=TCP DPT=65536","",0,false,true},
  {"zero port","FINAL_REJECT: IN=eth0 OUT= SRC=203.0.113.1 DST=192.0.2.1 PROTO=TCP DPT=0","",0,false,true},
  {"leading zero","FINAL_REJECT: IN=eth0 OUT= SRC=203.0.113.1 DST=192.0.2.1 PROTO=TCP DPT=022","",0,false,true},
  {"non TCP/UDP","FINAL_REJECT: IN=eth0 OUT= SRC=203.0.113.1 DST=192.0.2.1 PROTO=ICMP","",0,true,false},
  {"truncated",strings.Repeat("x",MaxLineBytes+1),"",0,false,true},
 }
 for _,tt:=range tests {t.Run(tt.name,func(t *testing.T){
  p,err:=ParseLine(tt.line)
  if tt.ignore {if !errors.Is(err,ErrIgnored){t.Fatalf("expected ignore, got %v",err)};return}
  if tt.invalid {if !errors.Is(err,ErrMalformed){t.Fatalf("expected malformed, got %v",err)};return}
  if err!=nil{t.Fatal(err)}
  if p.Transport!=tt.kind || p.DestinationPort!=tt.port || p.InInterface==""{t.Fatalf("unexpected packet: %+v",p)}
 })}
}
