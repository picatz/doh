package statedb

import (
	"crypto/sha256"
	"strconv"
	"testing"
	"time"

	"github.com/picatz/doh/internal/audit"
	"github.com/picatz/doh/internal/signin"
)

// The hot operations: what each admin request (a session read, a DPoP
// proof), each new device, each setup page, and each change costs.

func BenchmarkSessions(b *testing.B) {
	db, _ := openTest(b)
	s, ctx, now := db.Sessions(), b.Context(), time.Now()
	for i := range 1000 {
		if err := s.Put(ctx, sessionID(strconv.Itoa(i)), signin.SessionID{}, signin.StoredSession{
			Session:  signin.Session{Person: "p", Name: "n", Role: signin.RoleAdmin, Method: "passkey", Created: now, Expires: now.Add(time.Hour)},
			LastSeen: now,
		}, 1000); err != nil {
			b.Fatal(err)
		}
	}
	b.Run("get", func(b *testing.B) {
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			if _, ok, err := s.Get(ctx, sessionID(strconv.Itoa(i%1000))); !ok || err != nil {
				b.Fatal(ok, err)
			}
			i++
		}
	})
	b.Run("get/parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if _, ok, err := s.Get(ctx, sessionID(strconv.Itoa(i%1000))); !ok || err != nil {
					b.Error(ok, err)
					return
				}
				i++
			}
		})
	})
	b.Run("touch", func(b *testing.B) {
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			if err := s.Touch(ctx, sessionID(strconv.Itoa(i%1000)), now.Add(time.Duration(i))); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

func BenchmarkReplayCache_Seen(b *testing.B) {
	db, _ := openTest(b)
	cache, err := db.ReplayCache(b.Context(), "api", 50_000, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		// Fresh proofs, as every request has; the cache wraps around as
		// they expire.
		if seen, err := cache.Seen(b.Context(), "jti-"+strconv.Itoa(i), time.Now().Add(time.Millisecond)); seen || err != nil {
			b.Fatal(seen, err)
		}
		i++
	}
}

func BenchmarkSetupLinks_Lookup(b *testing.B) {
	db, _ := openTest(b)
	l, ctx, now := db.SetupLinks(), b.Context(), time.Now()
	for i := range 1000 {
		_ = l.Create(ctx, sha256.Sum256([]byte(strconv.Itoa(i))), SetupLink{Profile: "p", Expires: now.Add(time.Hour)}, now, 1000)
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if _, ok, err := l.Lookup(ctx, sha256.Sum256([]byte(strconv.Itoa(i%1000))), now); !ok || err != nil {
			b.Fatal(ok, err)
		}
		i++
	}
}

func BenchmarkAlertMemory(b *testing.B) {
	db, _ := openTest(b)
	m, ctx, now := db.AlertMemory(), b.Context(), time.Now()
	b.Run("see-known-device", func(b *testing.B) {
		for i := range 2000 {
			_, _, _ = m.SeeDevice(ctx, "", "client:"+strconv.Itoa(i), now)
		}
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			if isNew, _, err := m.SeeDevice(ctx, "", "client:"+strconv.Itoa(i%2000), now.Add(time.Duration(i))); isNew || err != nil {
				b.Fatal(isNew, err)
			}
			i++
		}
	})
	b.Run("claim", func(b *testing.B) {
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			if _, err := m.Claim(ctx, "", "threat", strconv.Itoa(i%5000), now.Add(time.Duration(i)*time.Second), time.Hour); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

func BenchmarkAudit(b *testing.B) {
	db, _ := openTest(b)
	store, ctx := db.Audit(), b.Context()
	e := audit.Event{
		Time: time.Now(), Tenant: "smiths", Action: "profile.updated",
		Actor:   audit.Actor{Kind: audit.ActorPerson, ID: "p1", Name: "Kent", Tenant: "smiths"},
		Target:  audit.Target{Type: "profile", ID: "kids"},
		Summary: "Unblocked TikTok (tiktok) in profile kids",
		Details: map[string]string{"profile": "kids", "services.removed": "tiktok"},
	}
	b.Run("record", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := store.Record(ctx, e); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("list-100", func(b *testing.B) {
		for range 10_000 - b.N {
			_ = store.Record(ctx, e)
		}
		b.ReportAllocs()
		for b.Loop() {
			if page, err := store.List(ctx, audit.Filter{Tenant: "smiths"}); err != nil || len(page.Events) != audit.DefaultLimit {
				b.Fatal(len(page.Events), err)
			}
		}
	})
}

// BenchmarkSeenDevices_Save is the worst a save every 30 seconds costs:
// every one of the 4,096 devices remembered changed, in one transaction,
// with the bound enforced.
func BenchmarkSeenDevices_Save(b *testing.B) {
	db, _ := openTest(b)
	d, ctx, now := db.SeenDevices(), b.Context(), time.Now()
	batch := make([]SeenDevice, 4096)
	for i := range batch {
		batch[i] = SeenDevice{Profile: "default", Client: "10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256), Transport: "udp", First: now, Last: now}
	}
	for b.Loop() {
		for i := range batch {
			batch[i].Last = batch[i].Last.Add(time.Second)
		}
		if err := d.Save(ctx, batch, 4096); err != nil {
			b.Fatal(err)
		}
	}
}
