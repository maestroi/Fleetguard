// Package agent owns durable signed desired-state recovery and reconciliation.
// The central controller never supplies state file paths or firewall rules.
package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

const (
	stateFilename = "desired-state-v1.json"
	maxStateBytes = protocol.MaxEnvelopeBytes + 4096
)

type DurableState struct {
	Version    int                      `json:"version"`
	Revision   uint64                   `json:"revision"`
	Signed     *protocol.SignedSnapshot `json:"signed,omitempty"`
	AcceptedAt time.Time                `json:"accepted_at,omitempty"`
}
type Store interface {
	Load() (DurableState, error)
	Save(DurableState) error
}
type FileStore struct {
	Dir         string
	RequireRoot bool
}

func (s FileStore) checkDir() error {
	if !filepath.IsAbs(s.Dir) || filepath.Clean(s.Dir) != s.Dir || s.Dir == "/" {
		return errors.New("state directory must be an absolute, clean, nonroot path")
	}
	info, err := os.Lstat(s.Dir)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be a nonsymlink private directory (0700)")
	}
	if s.RequireRoot {
		if os.Geteuid() != 0 {
			return errors.New("root required for enforcement state")
		}
		// Disabled verifies root ownership and symlink-free protected ancestors.
		// A latched disable is valid: only errors here are unsafe.
		if _, err := checkEmergencyDir(s.Dir); err != nil {
			return err
		}
	}
	return nil
}
func (s FileStore) Load() (DurableState, error) {
	if err := s.checkDir(); err != nil {
		return DurableState{}, err
	}
	path := filepath.Join(s.Dir, stateFilename)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return DurableState{Version: 1}, nil
	}
	if err != nil {
		return DurableState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return DurableState{}, errors.New("state file must be a private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || (s.RequireRoot && stat.Uid != 0) {
		return DurableState{}, errors.New("unsafe owner or hard-linked state file")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return DurableState{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return DurableState{}, err
	}
	if len(data) > maxStateBytes {
		return DurableState{}, errors.New("persisted state exceeds bound")
	}
	var state DurableState
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return DurableState{}, fmt.Errorf("decode persisted state: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return DurableState{}, errors.New("trailing state data")
	}
	if state.Version != 1 || (state.Revision == 0 && state.Signed != nil) || (state.Revision > 0 && (state.Signed == nil || state.AcceptedAt.IsZero())) {
		return DurableState{}, errors.New("invalid persisted signed-state watermark")
	}
	return state, nil
}
func (s FileStore) Save(state DurableState) error {
	if err := s.checkDir(); err != nil {
		return err
	}
	if state.Version != 1 || (state.Revision == 0 && state.Signed != nil) || (state.Revision > 0 && (state.Signed == nil || state.AcceptedAt.IsZero())) {
		return errors.New("invalid state for persistence")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > maxStateBytes {
		return errors.New("persisted state too large")
	}
	dir, err := os.Open(s.Dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	// Random private temp + O_EXCL avoids symlink path replacement. The
	// directory is exclusive to the agent; rename + fsync survives crashes.
	f, err := os.CreateTemp(s.Dir, ".desired-state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	_, err = f.Write(append(data, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	dest := filepath.Join(s.Dir, stateFilename)
	if info, err := os.Lstat(dest); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ok || stat.Nlink != 1 || (s.RequireRoot && stat.Uid != 0) {
			return errors.New("refusing to replace unsafe persisted state file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	return dir.Sync()
}
