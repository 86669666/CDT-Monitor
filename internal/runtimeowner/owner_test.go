package runtimeowner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestOwnerSubprocess(t *testing.T) {
	if os.Getenv("CDT_OWNER_TEST_HELPER") != "1" {
		t.Skip("helper")
	}
	owner, err := Acquire(os.Getenv("CDT_OWNER_TEST_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
}

func TestOwnerExcludesAliasesAndOtherProcesses(t *testing.T) {
	dir := t.TempDir()
	owner, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Owns(dir) {
		t.Fatal("owner not valid")
	}
	if second, err := Acquire(dir); err == nil {
		second.Close()
		t.Fatal("same-process competing owner allowed")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err = os.Symlink(dir, alias); err == nil {
		if second, err := Acquire(alias); err == nil {
			second.Close()
			t.Fatal("symlink bypassed ownership")
		}
	}
	attempt := func() error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestOwnerSubprocess$")
		cmd.Env = append(os.Environ(), "CDT_OWNER_TEST_HELPER=1", "CDT_OWNER_TEST_DIR="+dir)
		return cmd.Run()
	}
	if attempt() == nil {
		t.Fatal("second process acquired live owner")
	}
	if os.Getenv("CDT_CORE_LONG_OWNER") == "1" {
		started := time.Now()
		time.Sleep(121 * time.Second)
		if attempt() == nil {
			t.Fatal("owner was stolen after old recovery TTL")
		}
		t.Logf("live owner remains exclusive after %s", time.Since(started))
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	if attempt() != nil {
		t.Fatal("normal close did not release ownership")
	}
}
