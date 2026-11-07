// Package runtimeowner holds a non-expiring OS lock for one data directory.
package runtimeowner

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Owner struct {
	mu   sync.Mutex
	file *os.File
	dir  string
}

func Acquire(dataDir string) (*Owner, error) {
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, err
	}
	dir, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return nil, err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".runtime.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lock(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("data directory already owned or cannot be locked: %w", err)
	}
	return &Owner{file: f, dir: dir}, nil
}

func (o *Owner) Owns(dataDir string) bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	dir, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return false
	}
	dir, err = filepath.Abs(dir)
	return err == nil && o.file != nil && dir == o.dir
}

func (o *Owner) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.file == nil {
		return nil
	}
	err := o.file.Close() // OS releases the lock on close, exit, and SIGKILL.
	o.file = nil
	return err
}
