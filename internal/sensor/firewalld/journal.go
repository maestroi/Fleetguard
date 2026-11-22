package firewalld

import (
 "bufio"
 "context"
 "errors"
 "io"
 "log/slog"
 "os/exec"
 "time"

 "github.com/maestroi/Fleetguard/pkg/protocol"
)

// ScanLines consumes one line at a time without allowing oversized kernel
// messages to allocate memory or poison subsequent valid lines.
func ScanLines(ctx context.Context, input io.Reader, onLine func(string), onOversized func()) error {
 reader:=bufio.NewReaderSize(input,4096)
 line:=make([]byte,0,MaxLineBytes)
 tooLarge:=false
 for {
  if err:=ctx.Err();err!=nil{return err}
  fragment,err:=reader.ReadSlice('\n')
  if !tooLarge {
   if len(line)+len(fragment)>MaxLineBytes {tooLarge=true;line=line[:0]} else {line=append(line,fragment...)}
  }
  if err==nil || errors.Is(err,io.EOF){
   if tooLarge{onOversized()}else if len(line)>0{
    end:=len(line)
    if line[end-1]=='\n'{end--}
    if end>0 && line[end-1]=='\r'{end--}
    if end>0{onLine(string(line[:end]))}
   }
   line=line[:0];tooLarge=false
   if errors.Is(err,io.EOF){return nil}
   continue
  }
  if errors.Is(err,bufio.ErrBufferFull){continue}
  return err
 }
}

type EvidenceSink interface {
 SubmitEvidence(context.Context,protocol.Evidence)error
}

// RunJournal starts at the live end of the kernel journal; no historical
// replay, journal cursor storage, global firewalld configuration changes,
// privileged probes or shell evaluation. All counters and delivery are
// separate from the enforcement engine. An unavailable journal is optional.
func RunJournal(ctx context.Context,collector *Collector,sink EvidenceSink) {
 if collector==nil || sink==nil {return}
 outgoing:=make(chan protocol.Evidence,64)
 // Independent bounded network worker. Controller capacity is 32 evidence/s
 // per node; this sender emits at most 8/s, and intentionally never retries
 // unverified samples across windows or reconnections.
 go func(){
  throttle:=time.NewTicker(time.Second/8)
  defer throttle.Stop()
  for {
   select {
   case <-ctx.Done():return
   case event:=<-outgoing:
    select{case <-ctx.Done():return;case <-throttle.C:}
    if err:=sink.SubmitEvidence(ctx,event);err!=nil {
     collector.NoteSubmissionFailure()
     slog.Warn("firewalld telemetry submission failed","error",err)
    }
   }
  }
 }()
 // Time-driven aggregation prevents an idle or dead journal from retaining
 // source address metadata longer than one configured window.
 go func(){
  flush:=time.NewTicker(collector.Window())
  defer flush.Stop()
  for{
   select{
   case <-ctx.Done():return
   case now:=<-flush.C:
    batch:=collector.Flush(now)
    for _,item:=range batch {
     select{case outgoing<-item:default:collector.NoteQueueDrop()}
    }
   }
  }
 }()
 backoff:=time.Second
 for ctx.Err()==nil {
  // _TRANSPORT=kernel selects journal metadata, not the firewalld service
  // stdout. --lines=0 prevents reading historic packet logs on restart.
  cmd:=exec.CommandContext(ctx,"journalctl","--quiet","--no-pager","--follow","--lines=0","--output=cat","_TRANSPORT=kernel")
  cmd.Stderr=io.Discard
  pipe,err:=cmd.StdoutPipe()
  if err==nil {err=cmd.Start()}
  if err==nil {
   err=ScanLines(ctx,pipe,func(line string){collector.ObserveLine(line,time.Now())},collector.NoteOversized)
   if waitErr:=cmd.Wait();err==nil{err=waitErr}
  }
  if ctx.Err()!=nil {return}
  collector.NoteJournalFailure()
  slog.Warn("firewalld kernel journal unavailable; optional sensor retrying","error",err)
  timer:=time.NewTimer(backoff)
  select{case <-ctx.Done():timer.Stop();return;case <-timer.C:}
  if backoff<30*time.Second{backoff*=2}
  if backoff>time.Minute {backoff=time.Minute}
 }
}
