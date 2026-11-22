// Package exposure implements a local, audit-only baseline independently of
// signed temporary threat decisions. It contains NO firewall write operations.
package exposure

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/netip"
 "os"
 "regexp"
 "sort"
 "strings"
 "time"

 "github.com/maestroi/Fleetguard/pkg/protocol"
)

const SchemaVersion=1
const MaxDocumentBytes=256<<10
var identifier=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$`)
type PortRange struct{
 From uint16 `json:"from"`
 To uint16 `json:"to"`
}
func(r PortRange)Valid()bool{return r.From>0 && r.To>=r.From}
func(r PortRange)Contains(p uint16)bool{return p>=r.From && p<=r.To}
func(r PortRange)Overlaps(other PortRange)bool{return r.From<=other.To && other.From<=r.To}
type Entry struct {
 ID string `json:"id"`
 Direction string `json:"direction"`
 Transport protocol.Transport `json:"transport"`
 Ports PortRange `json:"ports,omitempty"`
 PortParameter string `json:"port_parameter,omitempty"`
 Source string `json:"source"`
 Zone string `json:"zone,omitempty"`
 Interface string `json:"interface,omitempty"`
 Intent string `json:"intent"`
 Condition string `json:"condition,omitempty"`
}
type Profile struct{
 Name string `json:"name"`
 Role string `json:"role,omitempty"`
 Group string `json:"group,omitempty"`
 Extends []string `json:"extends,omitempty"`
 Entries []Entry `json:"entries"`
}
type Override struct{
 Entry string `json:"entry"`
 Intent string `json:"intent"`
 Operator string `json:"operator"`
 Reason string `json:"reason"`
 ExpiresAt time.Time `json:"expires_at"`
}
type Document struct{
 Schema int `json:"schema"`
 NodeID string `json:"node_id"`
 Role string `json:"role"`
 Group string `json:"group"`
 Assigned []string `json:"assigned"`
 Profiles []Profile `json:"profiles"`
 Flags map[string]bool `json:"flags,omitempty"`
 PortParameters map[string]PortRange `json:"port_parameters,omitempty"`
 Overrides []Override `json:"overrides,omitempty"`
 // Local-only protected management boundaries, checked independently of
 // profile order, inheritance or operator exceptions.
 Protected []Entry `json:"protected,omitempty"`
}
type Rule struct{
 Entry
 Profile string `json:"profile"`
}
type Effective struct{
 NodeID string `json:"node_id"`
 Role string `json:"role"`
 Group string `json:"group"`
 Rules []Rule `json:"rules"`
}
func strict(data []byte,limit int,out any)error{
 if len(data)>limit{return errors.New("JSON exceeds size limit")}
 dec:=json.NewDecoder(bytes.NewReader(data))
 dec.DisallowUnknownFields()
 if err:=dec.Decode(out);err!=nil{return err}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{
  if err==nil{return errors.New("trailing JSON value")}
  return fmt.Errorf("trailing JSON: %w",err)
 }
 return nil
}
func Load(path string)(Document,error){
 // This file is a trusted LOCAL assignment; callers in privileged workflows
 // must also check ownership/ancestors before considering future enforcement.
 f,err:=os.Open(path);if err!=nil{return Document{},err}
 defer f.Close()
 b,err:=io.ReadAll(io.LimitReader(f,MaxDocumentBytes+1))
 if err!=nil{return Document{},err}
 var d Document
 if err:=strict(b,MaxDocumentBytes,&d);err!=nil{return Document{},err}
 return d,nil
}
func validSource(s string)bool {
 if s=="public" || s=="private" || s=="tailnet" || s=="loopback" || s=="any"{return true}
 if !strings.HasPrefix(s,"cidr:"){return false}
 raw:=strings.TrimPrefix(s,"cidr:")
 p,err:=netip.ParsePrefix(raw)
 return err==nil && p.IsValid() && !p.Addr().Is4In6() && p.Masked()==p && p.String()==raw
}
func validEntry(e Entry)error{
 if !identifier.MatchString(e.ID){return errors.New("invalid entry ID")}
 if e.Direction!="ingress" && e.Direction!="egress"{return errors.New("direction must be ingress or egress")}
 if e.Transport!=protocol.TransportTCP && e.Transport!=protocol.TransportUDP{return errors.New("transport must be tcp or udp")}
 if (e.PortParameter=="")==!e.Ports.Valid(){return errors.New("exactly one valid ports range or port_parameter is required")}
 if e.PortParameter!="" && (!identifier.MatchString(e.PortParameter) || e.Ports!=(PortRange{})){return errors.New("port parameter must replace the literal port range")}
 if !validSource(e.Source){return errors.New("source must be a known class or canonical cidr")}
 if e.Zone!="" && !identifier.MatchString(e.Zone){return errors.New("invalid firewall zone")}
 if e.Interface!="" && !identifier.MatchString(e.Interface){return errors.New("invalid interface")}
 if !validIntent(e.Intent){return errors.New("invalid intent")}
 if e.Condition!="" && !identifier.MatchString(e.Condition){return errors.New("invalid condition name")}
 return nil
}
func validIntent(s string)bool{return s=="required" || s=="permitted" || s=="forbidden"}
func sourceOverlap(a,b string)bool {
 if a==b || a=="any" || b=="any"{return true}
 if strings.HasPrefix(a,"cidr:") && strings.HasPrefix(b,"cidr:"){
  x,_:=netip.ParsePrefix(strings.TrimPrefix(a,"cidr:"))
  y,_:=netip.ParsePrefix(strings.TrimPrefix(b,"cidr:"))
  return x.Overlaps(y)
 }
 // Conservative: CIDRs may belong to multiple operator-defined network
 // classes. Reject contradictory combinations rather than assuming disjoint.
 if strings.HasPrefix(a,"cidr:") || strings.HasPrefix(b,"cidr:"){return true}
 return false
}
func overlap(a,b Rule)bool{
 if a.Direction!=b.Direction || a.Transport!=b.Transport || !a.Ports.Overlaps(b.Ports){return false}
 if a.Zone!="" && b.Zone!="" && a.Zone!=b.Zone{return false}
 if a.Interface!="" && b.Interface!="" && a.Interface!=b.Interface{return false}
 return sourceOverlap(a.Source,b.Source)
}
// Compile validates the *entire* assigned local document before emitting any
// expected policy. No remote policy, controller snapshot or network event may
// alter the assignment, operator override or protected path.
func Compile(d Document,now time.Time)(Effective,error){
 if d.Schema!=SchemaVersion || !identifier.MatchString(d.NodeID) || !identifier.MatchString(d.Role) || !identifier.MatchString(d.Group){
  return Effective{},errors.New("exposure: schema 1 and local node/role/group required")
 }
 if len(d.Profiles)==0 || len(d.Profiles)>64 || len(d.Assigned)==0 || len(d.Assigned)>16 || len(d.Overrides)>64 || len(d.Protected)>64 || len(d.Flags)>64 || len(d.PortParameters)>64{
  return Effective{},errors.New("exposure: profiles, assignments, flags or overrides exceed local limits")
 }
 for id,r:=range d.PortParameters{
  if !identifier.MatchString(id) || !r.Valid(){return Effective{},fmt.Errorf("exposure: invalid trusted port parameter %q",id)}
 }
 for id:=range d.Flags {if !identifier.MatchString(id){return Effective{},fmt.Errorf("exposure: invalid condition flag %q",id)}}
 profiles:=make(map[string]Profile,len(d.Profiles))
 for _,p:=range d.Profiles{
  if !identifier.MatchString(p.Name) || p.Role!="" && !identifier.MatchString(p.Role) || p.Group!="" && !identifier.MatchString(p.Group) || len(p.Entries)>128 || len(p.Extends)>16{
   return Effective{},fmt.Errorf("exposure: invalid profile %q",p.Name)
  }
  if _,exists:=profiles[p.Name];exists{return Effective{},fmt.Errorf("exposure: duplicate profile %q",p.Name)}
  seen:=map[string]bool{}
  for _,e:=range p.Entries {
   if err:=validEntry(e);err!=nil{return Effective{},fmt.Errorf("exposure: profile %s entry %s: %w",p.Name,e.ID,err)}
   if seen[e.ID]{return Effective{},fmt.Errorf("exposure: duplicate entry %s/%s",p.Name,e.ID)}
   seen[e.ID]=true
  }
  profiles[p.Name]=p
 }
 assigned:=make(map[string]bool)
 rules:=make([]Rule,0,256)
 visited:=map[string]bool{}
 walking:=map[string]bool{}
 var walk func(string)error
 walk=func(name string)error{
  if walking[name]{return fmt.Errorf("exposure: inheritance cycle at %s",name)}
  if visited[name]{return nil}
  p,ok:=profiles[name];if !ok{return fmt.Errorf("exposure: unknown assigned/inherited profile %q",name)}
  if p.Role!="" && p.Role!=d.Role || p.Group!="" && p.Group!=d.Group{return fmt.Errorf("exposure: profile %s not assigned to local role/group",name)}
  walking[name]=true
  for _,base:=range p.Extends{if err:=walk(base);err!=nil{return err}}
  delete(walking,name);visited[name]=true
  for _,e:=range p.Entries{
   if e.Condition!=""{
    enabled,known:=d.Flags[e.Condition]
    if !known{return fmt.Errorf("exposure: condition %q is not locally defined",e.Condition)}
    if !enabled{continue}
   }
   if e.PortParameter!=""{
    param,ok:=d.PortParameters[e.PortParameter]
    if !ok {return fmt.Errorf("exposure: missing trusted port parameter %q for %s/%s",e.PortParameter,name,e.ID)}
    e.Ports=param;e.PortParameter=""
   }
   rules=append(rules,Rule{Entry:e,Profile:name})
  }
  return nil
 }
 for _,name:=range d.Assigned {
  if assigned[name]{return Effective{},fmt.Errorf("exposure: duplicate assignment %s",name)}
  assigned[name]=true
  if err:=walk(name);err!=nil{return Effective{},err}
 }
 if len(rules)>1024{return Effective{},errors.New("exposure: too many composed rules")}
 byID:=make(map[string]int,len(rules))
 for i,r:=range rules{byID[r.Profile+"/"+r.ID]=i}
 seenOverrides:=map[string]bool{}
 for _,override:=range d.Overrides {
  if !identifier.MatchString(override.Operator) || !validIntent(override.Intent) || len(override.Reason)<8 || len(override.Reason)>256 || override.ExpiresAt.IsZero(){
   return Effective{},errors.New("exposure: override needs operator, intent, reason and expiration")
  }
  if seenOverrides[override.Entry]{return Effective{},fmt.Errorf("exposure: duplicate override %s",override.Entry)}
  seenOverrides[override.Entry]=true
  i,found:=byID[override.Entry]
  if !found{return Effective{},fmt.Errorf("exposure: override refers to missing or disabled entry %q",override.Entry)}
  if !override.ExpiresAt.After(now){continue} // expire exceptions by wall-clock time
  if override.ExpiresAt.After(now.Add(7*24*time.Hour)){return Effective{},fmt.Errorf("exposure: override %s exceeds seven-day local cap",override.Entry)}
  rules[i].Intent=override.Intent
 }
 for _,e:=range d.Protected {
  if err:=validEntry(e);err!=nil{return Effective{},fmt.Errorf("exposure: protected management path %s: %w",e.ID,err)}
  if e.PortParameter!="" || e.Condition!="" || e.Intent!="forbidden" {return Effective{},fmt.Errorf("exposure: protected path %s must be unconditional explicit forbidden rule",e.ID)}
  rules=append(rules,Rule{Entry:e,Profile:"local-protected"})
 }
 // Conflict detection rejects a contradictory *overlap*, not just identical
 // port numbers. It never silently chooses a permissive winner.
 for i:=range rules{
  for j:=0;j<i;j++{
   if rules[i].Intent!=rules[j].Intent && overlap(rules[i],rules[j]){
    return Effective{},fmt.Errorf("exposure: conflicting %s (%s) vs %s (%s) on overlapping %s/%d-%d source %s",
     rules[j].Profile+"/"+rules[j].ID,rules[j].Intent,rules[i].Profile+"/"+rules[i].ID,rules[i].Intent,
     rules[i].Transport,rules[i].Ports.From,rules[i].Ports.To,rules[i].Source)
   }
  }
 }
 sort.Slice(rules,func(i,j int)bool{
  a,b:=rules[i],rules[j]
  if a.Profile!=b.Profile{return a.Profile<b.Profile}
  return a.ID<b.ID
 })
 return Effective{NodeID:d.NodeID,Role:d.Role,Group:d.Group,Rules:rules},nil
}
