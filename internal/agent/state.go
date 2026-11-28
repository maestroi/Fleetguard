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

// readPrivate reads a bounded, private, single-link regular file from the
// checked state directory. Missing files return (nil, nil).
func (s FileStore) readPrivate(name string, limit int) ([]byte, error) {
	if err := s.checkDir(); err != nil {
		return nil, err
	}
	path := filepath.Join(s.Dir, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("state file must be a private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || (s.RequireRoot && stat.Uid != 0) {
		return nil, errors.New("unsafe owner or hard-linked state file")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("persisted state exceeds bound")
	}
	return data, nil
}

// decodeStrict rejects unknown fields and trailing data.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode persisted state: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing state data")
	}
	return nil
}

func (s FileStore) Load() (DurableState, error) {
	data, err := s.readPrivate(stateFilename, maxStateBytes)
	if err != nil {
		return DurableState{}, err
	}
	if data == nil {
		return DurableState{Version: 1}, nil
	}
	var state DurableState
	if err := decodeStrict(data, &state); err != nil {
		return DurableState{}, err
	}
	if state.Version != 1 || (state.Revision == 0 && state.Signed != nil) || (state.Revision > 0 && (state.Signed == nil || state.AcceptedAt.IsZero())) {
		return DurableState{}, errors.New("invalid persisted signed-state watermark")
	}
	return state, nil
}
func (s FileStore) Save(state DurableState) error {
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
	return s.writePrivate(stateFilename, data)
}

// writePrivate atomically replaces name with data: private temp file, fsync,
// rename, directory fsync. A crash leaves either the old or the new file.
func (s FileStore) writePrivate(name string, data []byte) error {
	if err := s.checkDir(); err != nil {
		return err
	}
	dir, err := os.Open(s.Dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	// Random private temp + O_EXCL avoids symlink path replacement. The
	// directory is exclusive to the agent; rename + fsync survives crashes.
	f, err := os.CreateTemp(s.Dir, ".state-*")
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
	dest := filepath.Join(s.Dir, name)
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
