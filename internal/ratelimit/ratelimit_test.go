package ratelimit

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"
)

func TestLimiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := &Limiter{Rate: 1, Burst: 3}

		for i := range 3 {
			if !l.Allow("a") {
				t.Fatalf("event %d of the burst refused", i)
			}
		}
		if l.Allow("a") {
			t.Fatal("event beyond the burst allowed")
		}
		if !l.Allow("b") {
			t.Fatal("another key was limited")
		}

		time.Sleep(time.Second)
		if !l.Allow("a") || l.Allow("a") {
			t.Fatal("a second didn't refill exactly one event")
		}

		time.Sleep(time.Hour)
		for i := range 3 {
			if !l.Allow("a") {
				t.Fatalf("refilled burst event %d refused", i)
			}
		}
		if l.Allow("a") {
			t.Fatal("refill exceeded the burst")
		}
	})
}

func TestLimiter_Limited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := &Limiter{Rate: 1, Burst: 2}

		if l.Limited("a") {
			t.Fatal("an unseen key is limited")
		}
		for range 2 {
			if l.Limited("a") || !l.Allow("a") {
				t.Fatal("the burst was refused")
			}
		}
		if !l.Limited("a") {
			t.Fatal("a key with no events left isn't limited")
		}
		// Asking doesn't use events up.
		for range 3 {
			l.Limited("a")
		}
		time.Sleep(time.Second)
		if l.Limited("a") || !l.Allow("a") || !l.Limited("a") {
			t.Fatal("a second didn't refill exactly one event")
		}
	})
}

func TestLimiter_BoundsKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := &Limiter{Rate: 1, Burst: 1, MaxKeys: 10}

		for i := range 10 {
			if !l.Allow(fmt.Sprint(i)) {
				t.Fatalf("key %d refused", i)
			}
		}
		// Every tracked bucket is in use, so new keys wait their turn
		// rather than growing the map.
		if l.Allow("new") {
			t.Fatal("tracked more keys than allowed")
		}
		if len(l.buckets) != 10 {
			t.Fatalf("%d keys tracked", len(l.buckets))
		}

		// Once buckets refill, they're forgotten to make room.
		time.Sleep(time.Second)
		if !l.Allow("new") {
			t.Fatal("new key refused after buckets refilled")
		}
		if len(l.buckets) > 10 {
			t.Fatalf("%d keys tracked", len(l.buckets))
		}
	})
}
