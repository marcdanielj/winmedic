package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// fakeNTP runs a time server whose clock is deliberately wrong by `off`, so the
// skew detection can be tested against a known answer rather than against
// whatever the machine running the tests thinks the time is.
func fakeNTP(t *testing.T, off time.Duration) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 64)
		for {
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 48 {
				continue
			}
			their := time.Now().Add(off)
			resp := make([]byte, 48)
			resp[0] = 0x1C // leap=0, version=3, mode=4 (server)
			resp[1] = 2    // stratum 2
			copy(resp[24:32], buf[40:48])
			binary.BigEndian.PutUint64(resp[32:], uint64(toNTP(their)))
			binary.BigEndian.PutUint64(resp[40:], uint64(toNTP(their)))
			_, _ = pc.WriteTo(resp, peer)
		}
	}()
	return pc.LocalAddr().String()
}

func TestNTPTimestampRoundTrip(t *testing.T) {
	want := time.Date(2026, 9, 16, 12, 34, 56, 500_000_000, time.UTC)
	got := toNTP(want).Time().UTC()
	// The wire format has ~233ps resolution; a millisecond is a generous bound.
	if d := got.Sub(want); d > time.Millisecond || d < -time.Millisecond {
		t.Errorf("round trip drifted by %v (%v -> %v)", d, want, got)
	}
}

// The skew grades are the whole point: five minutes is where Windows sign-in
// stops working, so the boundary has to be right in both directions.
func TestClockSkewGrading(t *testing.T) {
	for _, c := range []struct {
		name   string
		off    time.Duration
		want   Status
		expect string
	}{
		{"in sync", 0, StatusOK, ""}, // direction is noise at zero skew; do not assert it
		{"server 7m ahead: we are behind", 7 * time.Minute, StatusFail, "behind"},
		{"server 7m behind: we are ahead", -7 * time.Minute, StatusFail, "ahead of"},
		{"3m: past half the limit", 3 * time.Minute, StatusWarn, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := checkClock(fakeNTP(t, c.off), 2*time.Second)
			if got.Status != c.want {
				t.Fatalf("status = %v, want %v (summary %q)", got.Status, c.want, got.Summary)
			}
			if c.expect != "" && !contains(got.Summary, c.expect) {
				t.Errorf("summary %q should say %q", got.Summary, c.expect)
			}
			if c.want != StatusOK && got.Advice == "" {
				t.Error("a failing clock check must say how to fix it")
			}
		})
	}
}

// A silent or absent time service must not be reported as a healthy clock.
func TestClockUnreachableIsNotOK(t *testing.T) {
	got := checkClock("127.0.0.1:1", 300*time.Millisecond)
	if got.Status == StatusOK {
		t.Error("an unreachable time service was graded ok")
	}
}

// A UDP socket hears from anyone. A reply that is not an NTP server reply must
// never be turned into a time.
func TestNTPRejectsNonServerReply(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			_, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			junk := make([]byte, 48)
			junk[0] = 0x1B // mode 3: a client packet, not a server reply
			_, _ = pc.WriteTo(junk, peer)
		}
	}()
	if _, err := queryNTP(pc.LocalAddr().String(), time.Second); err == nil {
		t.Error("accepted a non-server packet as the time")
	}
}

// Stratum 0 is a refusal, not an answer, and its timestamps are meaningless.
func TestNTPRejectsKissOfDeath(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			_, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			kod := make([]byte, 48)
			kod[0] = 0x1C // server reply...
			kod[1] = 0    // ...but stratum 0: go away
			binary.BigEndian.PutUint64(kod[32:], uint64(toNTP(time.Now())))
			binary.BigEndian.PutUint64(kod[40:], uint64(toNTP(time.Now())))
			_, _ = pc.WriteTo(kod, peer)
		}
	}()
	if _, err := queryNTP(pc.LocalAddr().String(), time.Second); err == nil {
		t.Error("accepted a kiss-o'-death packet as the time")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
