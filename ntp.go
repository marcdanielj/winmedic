package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// KerberosMaxSkew is the default tolerance in Active Directory. Past this,
// Kerberos rejects the ticket and sign-in fails - typically with a message that
// says nothing about clocks, which is why this check exists at the top.
const KerberosMaxSkew = 5 * time.Minute

// ntpEpochOffset converts between NTP's 1900 epoch and Unix's 1970 epoch.
const ntpEpochOffset = 2208988800

// ntpTime is NTP's 64-bit fixed-point timestamp: 32 bits of seconds since 1900,
// 32 bits of fractional second.
type ntpTime uint64

func (t ntpTime) Time() time.Time {
	if t == 0 {
		return time.Time{}
	}
	sec := int64(t>>32) - ntpEpochOffset
	// The fraction is a binary fraction of a second, so scale by 1e9 and shift
	// rather than dividing - the arithmetic stays exact in integers.
	nsec := (int64(t&0xFFFFFFFF) * 1e9) >> 32
	return time.Unix(sec, nsec)
}

func toNTP(t time.Time) ntpTime {
	sec := uint64(t.Unix() + ntpEpochOffset)
	frac := (uint64(t.Nanosecond()) << 32) / 1e9
	return ntpTime(sec<<32 | frac)
}

// ClockResult is what the far end thinks the time is, relative to us.
type ClockResult struct {
	Offset time.Duration // positive: our clock is ahead of theirs
	RTT    time.Duration
	Server time.Time
	Strat  uint8
}

// queryNTP asks a time server for the time and computes our offset from it.
//
// The offset uses all four timestamps rather than simply comparing their clock
// to ours, because a naive comparison folds the network delay into the answer:
//
//	offset = ((t2 - t1) + (t3 - t4)) / 2
//
// t1/t4 are ours, t2/t3 are theirs. Averaging the two directions cancels a
// symmetric path delay, leaving the genuine clock difference. It is the same
// reasoning that lets one-way delay variation be measured between two machines
// whose clocks disagree.
func queryNTP(server string, timeout time.Duration) (ClockResult, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "123")
	}
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return ClockResult{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ClockResult{}, err
	}

	req := make([]byte, 48)
	req[0] = 0x1B // leap=0, version=3, mode=3 (client)
	t1 := time.Now()
	binary.BigEndian.PutUint64(req[40:], uint64(toNTP(t1)))

	if _, err := conn.Write(req); err != nil {
		return ClockResult{}, err
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return ClockResult{}, err
	}
	t4 := time.Now()

	mode := resp[0] & 0x7
	if mode != 4 && mode != 5 {
		// Mode 4 is a server reply; 5 is broadcast. Anything else is not an
		// answer to our question and must not be treated as the time.
		return ClockResult{}, fmt.Errorf("not an NTP server reply (mode %d)", mode)
	}
	stratum := resp[1]
	if stratum == 0 {
		// Stratum 0 in a reply is a "kiss-o'-death" packet: the server is
		// refusing, not answering, and its timestamps are meaningless.
		return ClockResult{}, errors.New("server refused the request (kiss-o'-death)")
	}

	t2 := ntpTime(binary.BigEndian.Uint64(resp[32:])).Time()
	t3 := ntpTime(binary.BigEndian.Uint64(resp[40:])).Time()
	if t2.IsZero() || t3.IsZero() {
		return ClockResult{}, errors.New("server returned empty timestamps")
	}

	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	rtt := t4.Sub(t1) - t3.Sub(t2)
	return ClockResult{
		// Reported from the client's point of view: positive means we are ahead.
		Offset: -offset,
		RTT:    rtt,
		Server: t3,
		Strat:  stratum,
	}, nil
}

// checkClock turns a time query into the advice a helpdesk needs.
func checkClock(server string, timeout time.Duration) Check {
	const name = "clock"
	res, err := queryNTP(server, timeout)
	if err != nil {
		return warn(name,
			fmt.Sprintf("could not reach the time service on %s", server),
			"UDP 123 may be blocked, or the server is not sharing time.\n"+
				"Without this, clock drift goes unnoticed until sign-in breaks.",
			err.Error())
	}

	skew := res.Offset
	if skew < 0 {
		skew = -skew
	}
	detail := fmt.Sprintf("server time %s · round trip %v", res.Server.Format(time.RFC3339), res.RTT.Round(time.Millisecond))

	switch {
	case skew >= KerberosMaxSkew:
		return fail(name,
			fmt.Sprintf("this PC is %s %s the domain controller", round(skew), aheadBehind(res.Offset)),
			fmt.Sprintf("Sign-in fails past %v of difference, usually with an error that never mentions the clock.\n", KerberosMaxSkew)+
				"Fix: point this PC at the domain for time, then resync.\n"+
				"  w32tm /config /syncfromflags:domhier /update\n"+
				"  w32tm /resync",
			detail)
	case skew >= KerberosMaxSkew/2:
		return warn(name,
			fmt.Sprintf("this PC is %s %s the domain controller", round(skew), aheadBehind(res.Offset)),
			fmt.Sprintf("Still working, but over half the %v limit - it will break if it keeps drifting.\n", KerberosMaxSkew)+
				"Run: w32tm /resync",
			detail)
	default:
		return ok(name, fmt.Sprintf("in sync (%s %s)", round(skew), aheadBehind(res.Offset)), detail)
	}
}

func aheadBehind(off time.Duration) string {
	if off >= 0 {
		return "ahead of"
	}
	return "behind"
}

func round(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}
