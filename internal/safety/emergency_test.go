package safety

import (
 "context"
 "os"
 "path/filepath"
 "testing"
 "time"

 "github.com/maestroi/Fleetguard/internal/firewall/mock"
 "github.com/maestroi/Fleetguard/pkg/protocol"
)

func TestEmergencyRemovesOnlyOwnedMockDecisionsOffline(t *testing.T) {
 ctx:=context.Background()
 now:=time.Date(2026,11,21,12,0,0,0,time.UTC)
 backend,err:=mock.New(func() time.Time{return now});if err!=nil{t.Fatal(err)}
 _,err=backend.Reconcile(ctx,[]protocol.Decision{{ID:"ban",Source:"203.0.113.1/32",Action:protocol.ActionDrop,Service:"ssh",Transport:protocol.TransportTCP,DestinationPorts:[]uint16{22},ExpiresAt:now.Add(time.Minute),ReasonCode:"lab_test"}})
 if err!=nil{t.Fatal(err)}
 dir:=t.TempDir()
 if err:=disable(ctx,dir,backend);err!=nil{t.Fatal(err)}
 if _,err:=os.Stat(filepath.Join(dir,disabledMarker));err!=nil{t.Fatal(err)}
 state,err:=backend.Inspect(ctx);if err!=nil{t.Fatal(err)}
 if len(state.Decisions)!=0{t.Fatalf("mock-owned bans remain: %+v",state)}
 if err:=disable(ctx,dir,backend);err!=nil{t.Fatal("idempotent disable: ",err)}
}
func TestEmergencyCannotFollowMarkerSymlink(t *testing.T) {
 dir:=t.TempDir()
 target:=filepath.Join(t.TempDir(),"victim")
 if err:=os.WriteFile(target,[]byte("original"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(target,filepath.Join(dir,disabledMarker));err!=nil{t.Fatal(err)}
 if err:=disable(context.Background(),dir,nil);err==nil{t.Fatal("accepted symlink marker")}
 data,err:=os.ReadFile(target);if err!=nil{t.Fatal(err)}
 if string(data)!="original"{t.Fatal("victim changed")}
}
func TestRootRequiredForProductionEmergency(t *testing.T) {
 if os.Geteuid()==0{t.Skip("CI is expected to run unprivileged")}
 if err:=EmergencyDisable(context.Background(),t.TempDir(),nil);err==nil{t.Fatal("non-root disable accepted")}
}
