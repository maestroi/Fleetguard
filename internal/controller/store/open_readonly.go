//go:build linux && cgo

package store

/*
#cgo LDFLAGS: -lsqlite3
#include <sqlite3.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

// OpenReadOnly does not initialize schemas, change PRAGMAs, or obtain any
// SQLite write capability. It is reserved for local operator inspection.
func OpenReadOnly(path string) (*DB, error) {
	if path == "" || path == ":memory:" {
		return nil, errors.New("existing SQLite file required")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, errors.New("SQLite parent must be private")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("SQLite inspection requires private regular non-symlink file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, errors.New("hard-linked SQLite file refused")
	}
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))
	var raw *C.sqlite3
	if rc := C.sqlite3_open_v2(name, &raw, C.SQLITE_OPEN_READONLY|C.SQLITE_OPEN_FULLMUTEX, nil); rc != C.SQLITE_OK {
		message := "SQLite read-only open failed"
		if raw != nil {
			message = fmt.Sprint(message, ": ", C.GoString(C.sqlite3_errmsg(raw)))
			C.sqlite3_close(raw)
		}
		return nil, errors.New(message)
	}
	C.sqlite3_busy_timeout(raw, 2000)
	return &DB{db: raw, retention: 24 * time.Hour}, nil
}
