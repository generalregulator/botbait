package ratelimit

import (
	"net/netip"
	"testing"
	"time"
)

func TestLimiterBurstAndRefill(t *testing.T) {
	l := New(1, 3, 24, 64)
	clock := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return clock }

	a := netip.MustParseAddr("203.0.113.7")
	for i := 0; i < 3; i++ {
		if !l.Allow(a) {
			t.Fatalf("burst token %d denied", i)
		}
	}
	if l.Allow(a) {
		t.Fatal("4th immediate connection must be denied")
	}
	clock = clock.Add(2 * time.Second)
	if !l.Allow(a) || !l.Allow(a) {
		t.Fatal("expected two refilled tokens after 2s")
	}
	if l.Allow(a) {
		t.Fatal("bucket should be empty again")
	}
}

func TestLimiterGroupsBySubnet(t *testing.T) {
	l := New(0.001, 2, 24, 64)
	if !l.Allow(netip.MustParseAddr("198.51.100.1")) || !l.Allow(netip.MustParseAddr("198.51.100.200")) {
		t.Fatal("two hosts of one /24 share a burst of 2")
	}
	if l.Allow(netip.MustParseAddr("198.51.100.77")) {
		t.Fatal("third host in the same /24 must be limited")
	}
	if !l.Allow(netip.MustParseAddr("198.51.101.1")) {
		t.Fatal("a different /24 must have its own bucket")
	}
}

func TestLimiterSweepAndBound(t *testing.T) {
	l := New(10, 1, 32, 128)
	clock := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return clock }
	l.maxKeys = 2

	l.Allow(netip.MustParseAddr("192.0.2.1"))
	l.Allow(netip.MustParseAddr("192.0.2.2"))
	if l.Allow(netip.MustParseAddr("192.0.2.3")) {
		t.Fatal("key space exhausted: must fail closed")
	}
	clock = clock.Add(5 * time.Second)
	l.Sweep()
	if l.Len() != 0 {
		t.Fatalf("idle buckets should be swept, have %d", l.Len())
	}
	if !l.Allow(netip.MustParseAddr("192.0.2.3")) {
		t.Fatal("new key must be admitted after sweep")
	}
}

func TestIPv4MappedIPv6SharesBucket(t *testing.T) {
	l := New(0.001, 1, 24, 64)
	if !l.Allow(netip.MustParseAddr("192.0.2.9")) {
		t.Fatal("first must pass")
	}
	if l.Allow(netip.MustParseAddr("::ffff:192.0.2.10")) {
		t.Fatal("v4-mapped address must map to the same /24 bucket")
	}
}

func TestGlobalBucket(t *testing.T) {
	g := NewBucket(0.001, 2)
	if !g.Allow() || !g.Allow() {
		t.Fatal("burst of 2 expected")
	}
	if g.Allow() {
		t.Fatal("third must be denied")
	}
}
