package firewalld

import (
 "crypto/rand"
 "encoding/hex"
 "errors"
 "fmt"
 "sort"
 "sync"
 "time"

 "github.com/maestroi/Fleetguard/pkg/protocol"
)

type Binding struct {
 Service string `json:"service"`
 Transport protocol.Transport `json:"transport"`
 Port uint16 `json:"port"`
}
type Config struct {
 Enabled bool `json:"enabled"`
 WindowSeconds int `json:"window_seconds"`
 MaxSources int `json:"max_sources"`
 MaxPacketsPerWindow int `json:"max_packets_per_window"`
 MaxReportsPerWindow int `json:"max_reports_per_window"`
 Bindings []Binding `json:"bindings"`
}
func (c Config) Validate() error {
 if !c.Enabled {return errors.New("sensor: disabled settings must be omitted entirely or enabled explicitly")}
 if c.WindowSeconds<1 || c.WindowSeconds>60 {return errors.New("sensor: window_seconds must be 1-60")}
 if c.MaxSources<1 || c.MaxSources>2048 {return errors.New("sensor: max_sources must be 1-2048")}
 if c.MaxPacketsPerWindow<1 || c.MaxPacketsPerWindow>100000 {return errors.New("sensor: max_packets_per_window must be 1-100000")}
 if c.MaxReportsPerWindow<1 || c.MaxReportsPerWindow>128 {return errors.New("sensor: max_reports_per_window must be 1-128")}
 if len(c.Bindings)<1 || len(c.Bindings)>64 {return errors.New("sensor: 1-64 explicit service bindings required")}
 seen:=make(map[portKey]bool,len(c.Bindings))
 for _,b:=range c.Bindings {
  if b.Service=="" || len(b.Service)>128 || !validService(b.Service) ||
   (b.Transport!=protocol.TransportTCP && b.Transport!=protocol.TransportUDP) || b.Port==0 {
   return errors.New("sensor: service/transport/port binding is invalid")
  }
  key:=portKey{b.Transport,b.Port}
  if seen[key] {return errors.New("sensor: ambiguous port binding")}
  seen[key]=true
 }
 return nil
}
func validService(s string)bool {
 for _,ch:=range s {
  if !(ch>='A'&&ch<='Z'||ch>='a'&&ch<='z'||ch>='0'&&ch<='9'||ch=='_'||ch=='-'||ch=='.'||ch==':' ){return false}
 }
 return (s[0]>='A' && s[0]<='Z') || (s[0]>='a' && s[0]<='z') || (s[0]>='0' && s[0]<='9') // v1 identifier prefix
}
type portKey struct {transport protocol.Transport;port uint16}
type sourceKey struct {source string;service string;transport protocol.Transport}
type bucket struct {
 attempts int
 ports map[uint16]bool
}
type Stats struct {
 LinesTotal uint64 `json:"lines_total"`
 Parsed uint64 `json:"parsed"`
 Ignored uint64 `json:"ignored"`
 Malformed uint64 `json:"malformed"`
 Oversized uint64 `json:"oversized"`
 Unmapped uint64 `json:"unmapped"`
 DroppedPackets uint64 `json:"dropped_packets"`
 DroppedSources uint64 `json:"dropped_sources"`
 DroppedPorts uint64 `json:"dropped_ports"`
 DroppedReports uint64 `json:"dropped_reports"`
 Emitted uint64 `json:"emitted"`
 QueueDropped uint64 `json:"queue_dropped"`
 SubmitFailed uint64 `json:"submit_failed"`
 JournalFailures uint64 `json:"journal_failures"`
 ActiveSources int `json:"active_sources"`
}
type Collector struct {
 mu sync.Mutex
 node string
 cfg Config
 byPort map[portKey]string
 active map[sourceKey]*bucket
 stats Stats
 start time.Time
 sequence uint64
 windowPackets int
 session string
}
func NewCollector(node string,cfg Config)(*Collector,error){
 if node=="" {return nil,errors.New("sensor: node ID required")}
 if err:=cfg.Validate();err!=nil{return nil,err}
 random:=make([]byte,12)
 if _,err:=rand.Read(random);err!=nil{return nil,err}
 p:=make(map[portKey]string,len(cfg.Bindings))
 for _,binding:=range cfg.Bindings {p[portKey{binding.Transport,binding.Port}]=binding.Service}
 return &Collector{node:node,cfg:cfg,byPort:p,active:make(map[sourceKey]*bucket),session:hex.EncodeToString(random)},nil
}
func (c *Collector) Window()time.Duration{return time.Duration(c.cfg.WindowSeconds)*time.Second}
func (c *Collector) Stats()Stats {c.mu.Lock();defer c.mu.Unlock();s:=c.stats;s.ActiveSources=len(c.active);return s}
func (c *Collector) NoteOversized(){c.mu.Lock();c.stats.LinesTotal++;c.stats.Oversized++;c.mu.Unlock()}
func (c *Collector) NoteQueueDrop(){c.mu.Lock();c.stats.QueueDropped++;c.mu.Unlock()}
func (c *Collector) NoteSubmissionFailure(){c.mu.Lock();c.stats.SubmitFailed++;c.mu.Unlock()}
func (c *Collector) NoteJournalFailure(){c.mu.Lock();c.stats.JournalFailures++;c.mu.Unlock()}

// ObserveLine is safe to call from the bounded journal reader. Only counters
// and normalized address/port metadata are retained, never kernel payloads.
func (c *Collector) ObserveLine(line string, now time.Time){
 packet,err:=ParseLine(line)
 c.mu.Lock();defer c.mu.Unlock()
 c.stats.LinesTotal++
 if errors.Is(err,ErrIgnored){c.stats.Ignored++;return}
 if err!=nil{c.stats.Malformed++;return}
 c.stats.Parsed++
 service,ok:=c.byPort[portKey{packet.Transport,packet.DestinationPort}]
 if !ok {c.stats.Unmapped++;return}
 if c.start.IsZero(){c.start=now}
 // Time-window advancement is normally driven by a separate ticker. Never
 // silently mix packets from widely separated windows on a stalled reader.
 if now.Before(c.start) || now.Sub(c.start)>=c.Window() {
  c.stats.DroppedPackets++
  return
 }
 if c.statsPackets()>=c.cfg.MaxPacketsPerWindow {c.stats.DroppedPackets++;return}
 key:=sourceKey{packet.Source.String(),service,packet.Transport}
 b,exists:=c.active[key]
 if !exists {
  if len(c.active)>=c.cfg.MaxSources {c.stats.DroppedSources++;return}
  b=&bucket{ports:make(map[uint16]bool)}
  c.active[key]=b
 }
 if !b.ports[packet.DestinationPort] && len(b.ports)>=protocol.MaxPortsPerEvent {
  c.stats.DroppedPorts++
  return
 }
 b.ports[packet.DestinationPort]=true
 b.attempts++
 c.windowPackets++
}
func (c *Collector) statsPackets()int{return c.windowPackets}
// Flush emits a bounded, deterministic sample and resets all per-window state.
// EventID/DedupKey are unique per agent process and consecutive windows, which
// supports controller deduplication without storing source IPs in identifiers.
func (c *Collector) Flush(now time.Time) []protocol.Evidence {
 c.mu.Lock();defer c.mu.Unlock()
 if c.start.IsZero(){c.start=now}
 if !now.After(c.start){return nil}
 elapsed:=now.Sub(c.start)
 if elapsed<time.Second{return nil}
 seconds:=int(elapsed/time.Second)
 if seconds<1 {seconds=1}
 if seconds>c.cfg.WindowSeconds {seconds=c.cfg.WindowSeconds}
 keys:=make([]sourceKey,0,len(c.active))
 for key:=range c.active {keys=append(keys,key)}
 sort.Slice(keys,func(i,j int)bool{
  a,b:=c.active[keys[i]].attempts,c.active[keys[j]].attempts
  if a!=b{return a>b}
  if keys[i].source!=keys[j].source{return keys[i].source<keys[j].source}
  if keys[i].service!=keys[j].service{return keys[i].service<keys[j].service}
  return keys[i].transport<keys[j].transport
 })
 max:=c.cfg.MaxReportsPerWindow
 if len(keys)>max {c.stats.DroppedReports+=uint64(len(keys)-max);keys=keys[:max]}
 result:=make([]protocol.Evidence,0,len(keys))
 for _,key:=range keys{
  b:=c.active[key]
  ports:=make([]uint16,0,len(b.ports));for p:=range b.ports{ports=append(ports,p)}
  sort.Slice(ports,func(i,j int)bool{return ports[i]<ports[j]})
  c.sequence++
  id:=fmt.Sprintf("fw-%s-%016x",c.session,c.sequence)
  result=append(result,protocol.Evidence{
   Schema:protocol.SchemaVersion,EventID:id,DedupKey:id,NodeID:c.node,ObservedAt:now,
   WindowSeconds:seconds,SourceIP:key.source,Service:key.service,Transport:key.transport,
   DestinationPorts:ports,Observation:"firewalld_denied_packets",Attempts:b.attempts,
   ProofLevel:protocol.ProofUnverifiedLog,
  })
 }
 c.stats.Emitted+=uint64(len(result))
 c.start=now
 c.active=make(map[sourceKey]*bucket)
 c.windowPackets=0
 return result
}
