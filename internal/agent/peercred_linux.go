//go:build linux

package agent

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID returns the effective UID of the process on the other end of a Unix
// socket connection, using SO_PEERCRED. The kernel supplies this; a client
// cannot forge it.
func PeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("agent: peer credentials: %w", err)
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("agent: peer credentials: %w", err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("agent: peer credentials: %w", credErr)
	}
	return cred.Uid, nil
}
