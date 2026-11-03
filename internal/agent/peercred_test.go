package agent

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPeerUIDReportsPeerProcessUID(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socketpair unavailable: %v", err)
	}
	f0 := os.NewFile(uintptr(fds[0]), "s0")
	f1 := os.NewFile(uintptr(fds[1]), "s1")
	defer f0.Close()
	defer f1.Close()

	// FileConn duplicates fd. Original belongs exclusively to os.File;
	// never also unix.Close it (finalizer could close a reused descriptor).
	c0, err := net.FileConn(f0)
	if err != nil {
		t.Fatal(err)
	}
	defer c0.Close()
	uc, ok := c0.(*net.UnixConn)
	if !ok {
		t.Fatalf("expected *net.UnixConn, got %T", c0)
	}

	uid, err := PeerUID(uc)
	if err != nil {
		t.Fatal(err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("PeerUID = %d, want %d", uid, os.Getuid())
	}
}
