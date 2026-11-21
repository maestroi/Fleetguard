package agent

import (
 "bytes"
 "context"
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "os"
 "time"

 "github.com/maestroi/Fleetguard/pkg/protocol"
)

type Transport struct {
 http *http.Client
 base string
 token string
 node string
 group string
}
// NewTransport authenticates the controller using system-independent pinned
// local CA roots and a per-node bearer token. No redirects, proxies, HTTP,
// insecure TLS mode, or controller-directed URLs are supported.
func NewTransport(c RuntimeConfig,token string)(*Transport,error) {
 pem,err:=os.ReadFile(c.TLSCAFile);if err!=nil{return nil,err}
 roots:=x509.NewCertPool()
 if !roots.AppendCertsFromPEM(pem){return nil,errors.New("invalid/pempty trusted TLS CA")}
 client:=&http.Client{
  Timeout:5*time.Second,
  CheckRedirect:func(*http.Request,[]*http.Request)error{return errors.New("redirect refused")},
  Transport:&http.Transport{
   Proxy:nil,MaxIdleConns:2,MaxIdleConnsPerHost:2,IdleConnTimeout:15*time.Second,
   DialContext:(&net.Dialer{Timeout:3*time.Second,KeepAlive:15*time.Second}).DialContext,
   TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS13,RootCAs:roots},
  },
 }
 return &Transport{http:client,base:c.ControllerURL,token:token,node:c.NodeID,group:c.ServiceGroup},nil
}
func (t *Transport) endpoint(path string)string {
 q:=url.Values{"group":{t.group}}
 return t.base+path+"?"+q.Encode()
}
func (t *Transport) request(ctx context.Context,method,path string,body []byte)([]byte,error) {
 var r io.Reader
 if body!=nil {r=bytes.NewReader(body)}
 req,err:=http.NewRequestWithContext(ctx,method,t.endpoint(path),r)
 if err!=nil{return nil,err}
 req.Header.Set("Authorization","Bearer "+t.token)
 req.Header.Set("X-Fleetguard-Node-ID",t.node)
 req.Header.Set("Accept","application/json")
 if body!=nil {req.Header.Set("Content-Type","application/json")}
 resp,err:=t.http.Do(req)
 if err!=nil{return nil,err}
 defer resp.Body.Close()
 if resp.StatusCode!=http.StatusOK {return nil,fmt.Errorf("controller %s: HTTP %d",path,resp.StatusCode)}
 limit:=int64(protocol.MaxEnvelopeBytes+1)
 if body!=nil {limit=4<<10}
 content,err:=io.ReadAll(io.LimitReader(resp.Body,limit))
 if err!=nil{return nil,err}
 if len(content)>=int(limit){return nil,errors.New("controller response exceeds bound")}
 return content,nil
}
func (t *Transport) Fetch(ctx context.Context)(protocol.SignedSnapshot,error) {
 wire,err:=t.request(ctx,"GET","/v1/snapshot",nil)
 if err!=nil{return protocol.SignedSnapshot{},err}
 return protocol.DecodeSignedSnapshot(wire)
}
func (t *Transport) Acknowledge(ctx context.Context,ack protocol.Acknowledgement)error{
 if err:=protocol.ValidateAcknowledgement(ack);err!=nil{return err}
 raw,err:=json.Marshal(ack);if err!=nil{return err}
 _,err=t.request(ctx,"POST","/v1/ack",raw)
 return err
}
func (t *Transport) Close() {
 if tr,ok:=t.http.Transport.(*http.Transport);ok{tr.CloseIdleConnections()}
}
