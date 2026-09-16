package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeResolver struct {
	srv []*net.SRV
	err error
}

func (f fakeResolver) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", f.srv, f.err
}
func (f fakeResolver) LookupHost(context.Context, string) ([]string, error) { return nil, nil }

func TestDiscoverDCsOrdersByPriority(t *testing.T) {
	r := fakeResolver{srv: []*net.SRV{
		{Target: "dc3.corp.example.com.", Port: 389, Priority: 10},
		{Target: "dc1.corp.example.com.", Port: 389, Priority: 0},
		{Target: "dc2.corp.example.com.", Port: 389, Priority: 5},
	}}
	hosts, c := discoverDCs(context.Background(), r, "corp.example.com")
	if c.Status != StatusOK {
		t.Fatalf("status = %v, want ok", c.Status)
	}
	if len(hosts) != 3 {
		t.Fatalf("got %d hosts, want 3", len(hosts))
	}
	// A client tries lowest priority first, so the tool must test that one.
	if hosts[0] != "dc1.corp.example.com" {
		t.Errorf("first host = %q, want the priority-0 DC", hosts[0])
	}
	if strings.HasSuffix(hosts[0], ".") {
		t.Error("trailing dot from the DNS record leaked into the hostname")
	}
}

// The most common real cause: the PC is asking a resolver that has never heard
// of the domain. The advice has to name that, or the check is just noise.
func TestDiscoverDCsFailsHelpfully(t *testing.T) {
	for _, r := range []fakeResolver{
		{err: errors.New("no such host")},
		{srv: nil},
	} {
		hosts, c := discoverDCs(context.Background(), r, "corp.example.com")
		if c.Status != StatusFail {
			t.Errorf("status = %v, want fail", c.Status)
		}
		if len(hosts) != 0 {
			t.Errorf("got %d hosts on a failed lookup", len(hosts))
		}
		if !strings.Contains(c.Advice, "DNS") {
			t.Errorf("advice does not mention DNS: %q", c.Advice)
		}
	}
}

// listen opens real listeners so the open-port path is exercised, not just the
// failure path.
func listen(t *testing.T, n int) (host string, ports []uint16) {
	t.Helper()
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		ap := ln.Addr().(*net.TCPAddr)
		host = ap.IP.String()
		ports = append(ports, uint16(ap.Port))
	}
	return host, ports
}

func TestPortsAllOpen(t *testing.T) {
	host, ports := listen(t, 3)
	spec := []adPort{
		{ports[0], "Kerberos", "signing in", false},
		{ports[1], "LDAP", "reading the directory", false},
		{ports[2], "SMB", "file shares", false},
	}
	c := checkPorts(context.Background(), host, spec, time.Second)
	if c.Status != StatusOK {
		t.Fatalf("status = %v, want ok (%s)", c.Status, c.Summary)
	}
}

// A blocked required port is a failure; a blocked optional one is only a
// warning. Grading them the same would either cry wolf or hide a real outage.
func TestPortsRequiredVersusOptional(t *testing.T) {
	host, ports := listen(t, 1)
	closed := closedPort(t)

	required := checkPorts(context.Background(), host, []adPort{
		{ports[0], "LDAP", "reading the directory", false},
		{closed, "SMB", "file shares and group policy delivery", false},
	}, 500*time.Millisecond)
	if required.Status != StatusFail {
		t.Errorf("a blocked required port graded %v, want fail", required.Status)
	}
	if !strings.Contains(required.Advice, "file shares") {
		t.Errorf("advice must say what breaks, got %q", required.Advice)
	}

	optional := checkPorts(context.Background(), host, []adPort{
		{ports[0], "LDAP", "reading the directory", false},
		{closed, "kpasswd", "changing passwords", true},
	}, 500*time.Millisecond)
	if optional.Status != StatusWarn {
		t.Errorf("a blocked optional port graded %v, want warn", optional.Status)
	}
}

func closedPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close() // nothing is listening there now
	return p
}

func TestPortDetailListsEveryPort(t *testing.T) {
	host, ports := listen(t, 2)
	spec := []adPort{
		{ports[0], "LDAP", "x", false},
		{ports[1], "SMB", "y", false},
	}
	c := checkPorts(context.Background(), host, spec, time.Second)
	if len(c.Detail) != 2 {
		t.Fatalf("got %d detail rows, want one per port", len(c.Detail))
	}
	for _, p := range ports {
		if !strings.Contains(strings.Join(c.Detail, "\n"), fmt.Sprint(p)) {
			t.Errorf("detail is missing port %d", p)
		}
	}
}
