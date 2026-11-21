package safety

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/maestroi/Fleetguard/internal/firewall"
)

const disabledMarker = "emergency-disabled"

// checkRootPath prevents unsafe config/kill-switch paths under symlinked or
// writable ancestors. The operator must pre-create the root-owned state dir.
func checkRootPath(path string, directory bool) error {
	if os.Geteuid() != 0 {
		return errors.New("root is required for local safety control")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be absolute and clean")
	}
	if directory && path == "/" {
		return errors.New("root directory cannot be agent state")
	}
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in protected path %s", current)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return fmt.Errorf("path %s must be owned by root", current)
		}
		if info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("path %s is group/world writable", current)
		}
		if current == path {
			if directory && !info.IsDir() {
				return errors.New("state directory is not a directory")
			}
			if !directory && !info.Mode().IsRegular() {
				return errors.New("policy is not a regular file")
			}
			if !directory && info.Mode().Perm()&0077 != 0 {
				return errors.New("local policy must not be group/world readable")
			}
		} else if !info.IsDir() {
			return fmt.Errorf("ancestor %s is not a directory", current)
		}
		if current == "/" {
			break
		}
		current = filepath.Dir(current)
	}
	return nil
}

// Disabled checks the local, root-owned latch. Any error MUST prevent
// enforcement, not be interpreted as "enabled".
func Disabled(stateDir string) (bool, error) {
	if err := checkRootPath(stateDir, true); err != nil {
		return false, err
	}
	path := filepath.Join(stateDir, disabledMarker)
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := checkRootPath(path, false); err != nil {
		return false, err
	}
	return true, nil
}

// EmergencyDisable works with no controller, network, shell, or firewalld
// reload. It latches disabled FIRST and only then asks the selected backend to
// remove *its own* temporary state. A nil backend is valid only until issue #8
// ships a real adapter; callers must not report rules removed in that case.
func EmergencyDisable(ctx context.Context, stateDir string, backend firewall.Backend) error {
	if err := checkRootPath(stateDir, true); err != nil {
		return err
	}
	return disable(ctx, stateDir, backend)
}

// disable assumes the caller already verified a secure state directory.
// Kept separate to allow rootless filesystem/owned-backend tests.
func disable(ctx context.Context, stateDir string, backend firewall.Backend) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(stateDir, disabledMarker)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			return errors.New("unsafe pre-existing emergency marker")
		}
	} else if err != nil {
		return fmt.Errorf("create emergency marker: %w", err)
	}
	if f != nil {
		_, err = f.WriteString(time.Now().UTC().Format(time.RFC3339Nano) + "\n")
		if err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("persist emergency marker: %w", err)
		}
	}
	if backend != nil {
		if err := backend.RemoveOwned(ctx); err != nil {
			return fmt.Errorf("kill switch latched, but removal of owned rules failed: %w", err)
		}
	}
	return nil
}
