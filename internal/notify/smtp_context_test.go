package notify

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
)

// Real loopback peers stop replying at each blocking SMTP boundary. No mail
// leaves the process; EOF on the peer verifies cancellation closes the socket.
func TestSMTPContextInterruptsStalledPeer(t *testing.T) {
	for _, phase := range []string{"greeting", "implicit-tls", "starttls-command", "starttls-handshake", "mail", "rcpt", "data", "data-result", "quit"} {
		for _, mode := range []string{"cancel", "deadline"} {
			t.Run(phase+"/"+mode, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				ready := make(chan struct{})
				peerDone := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						peerDone <- err
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					reader := bufio.NewReader(conn)
					stall := func() {
						// Consume ClientHello before canceling: this tests waiting for the TLS reply.
						if phase == "implicit-tls" || phase == "starttls-handshake" {
							var header [5]byte
							if _, err := io.ReadFull(reader, header[:]); err != nil {
								peerDone <- err
								return
							}
							if _, err := io.CopyN(io.Discard, reader, int64(binary.BigEndian.Uint16(header[3:]))); err != nil {
								peerDone <- err
								return
							}
						}
						close(ready)
						_, err := io.Copy(io.Discard, reader)
						peerDone <- err
					}
					if phase == "greeting" || phase == "implicit-tls" {
						stall()
						return
					}
					fmt.Fprint(conn, "220 localhost SMTP\r\n")
					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							peerDone <- err
							return
						}
						command := strings.Fields(line)[0]
						switch command {
						case "EHLO":
							fmt.Fprint(conn, "250-localhost\r\n250 STARTTLS\r\n")
						case "STARTTLS":
							if phase == "starttls-handshake" {
								fmt.Fprint(conn, "220 Ready for TLS\r\n")
							}
							stall()
							return
						case "MAIL":
							if phase == "mail" {
								stall()
								return
							}
							fmt.Fprint(conn, "250 OK\r\n")
						case "RCPT":
							if phase == "rcpt" {
								stall()
								return
							}
							fmt.Fprint(conn, "250 OK\r\n")
						case "DATA":
							if phase == "data" {
								stall()
								return
							}
							fmt.Fprint(conn, "354 Send data\r\n")
							for {
								line, err = reader.ReadString('\n')
								if err != nil {
									peerDone <- err
									return
								}
								if line == ".\r\n" {
									break
								}
							}
							if phase == "data-result" {
								stall()
								return
							}
							fmt.Fprint(conn, "250 OK\r\n")
						case "QUIT":
							stall()
							return
						default:
							peerDone <- fmt.Errorf("unexpected command %q", command)
							return
						}
					}
				}()
				ctx, cancel := context.WithCancel(context.Background())
				if mode == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
				}
				defer cancel()
				security := "none"
				if phase == "implicit-tls" {
					security = "ssl"
				}
				if strings.HasPrefix(phase, "starttls-") {
					security = "starttls"
				}
				done := make(chan error, 1)
				go func() {
					done <- sendEmail(ctx, domain.EmailConfig{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Username: "test@example.invalid", To: "test@example.invalid", Security: security}, domain.NotificationEvent{Title: "local cancellation test"})
				}()
				select {
				case <-ready:
				case err := <-peerDone:
					t.Fatalf("peer failed before stall: %v", err)
				case <-time.After(time.Second):
					t.Fatal("peer did not reach stall")
				}
				started := time.Now()
				if mode == "cancel" {
					cancel()
				}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("stalled send succeeded")
					}
					t.Logf("interrupted after %s: %v", time.Since(started), err)
				case <-time.After(time.Second):
					t.Fatal("SMTP send ignored context")
				}
				select {
				case err := <-peerDone:
					if err != nil {
						t.Fatalf("peer did not observe clean socket closure: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("SMTP socket remains open")
				}
			})
		}
	}
}
