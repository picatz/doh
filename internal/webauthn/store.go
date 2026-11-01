package webauthn

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/picatz/doh/internal/cose"
)

// CeremonyKey identifies a pending ceremony in a [ChallengeStore]. Tenant is
// [Config.Tenant] (the RP ID by default), so relying parties for many tenants
// can share one store without collisions. ID is an opaque lookup key derived
// from the ceremony ID returned to the browser and the session binding; it is
// not the ceremony ID itself, so a store never sees the binding.
type CeremonyKey struct {
	Tenant string
	ID     string
}

// Ceremony is the trusted server-side state of a pending ceremony. It holds
// no secret, but it must stay on the server: a ceremony accepted from the
// client would let the client choose its own challenge.
type Ceremony struct {
	Kind CeremonyKind `json:"kind"`
	// RPID is the relying party ID the options named.
	RPID string `json:"rpId"`
	// Challenge is the 32 random bytes sent in the options.
	Challenge []byte `json:"challenge"`
	// UserHandle is the account the ceremony is for. For authentication it
	// is empty when the user was not identified beforehand (discoverable,
	// usernameless login).
	UserHandle []byte `json:"userHandle,omitempty"`
	// AllowCredentials lists the credential IDs offered for authentication.
	AllowCredentials [][]byte `json:"allowCredentials,omitempty"`
	// UserVerification is the requirement sent in the options.
	UserVerification UserVerification `json:"userVerification"`
	// Algorithms are the pubKeyCredParams offered for registration.
	Algorithms []cose.Algorithm `json:"algorithms,omitempty"`
	// Mediation is the mediation requested for authentication.
	Mediation Mediation `json:"mediation,omitempty"`
	// Expires is when the ceremony stops being usable.
	Expires time.Time `json:"expires"`
	// ConfigHash fingerprints the relying party settings the ceremony began
	// under (see [Config.Tenant]). A relying party whose settings differ
	// rejects the ceremony with [ErrChallenge].
	ConfigHash []byte `json:"configHash"`
}

func (c Ceremony) clone() Ceremony {
	c.ConfigHash = bytes.Clone(c.ConfigHash)
	c.Challenge = bytes.Clone(c.Challenge)
	c.UserHandle = bytes.Clone(c.UserHandle)
	c.AllowCredentials = slices.Clone(c.AllowCredentials)
	for i := range c.AllowCredentials {
		c.AllowCredentials[i] = bytes.Clone(c.AllowCredentials[i])
	}
	c.Algorithms = slices.Clone(c.Algorithms)
	return c
}

// ChallengeStore holds pending ceremonies between begin and finish. The
// relying party owns no state itself; this interface is the only place a
// challenge lives.
//
// Put must store a copy of ceremony and fail, without replacing anything,
// if key is already present.
//
// Consume must atomically find key, delete it and return it, so that at
// most one Consume for a key ever succeeds, across every process sharing the
// store. It must return [ErrChallenge] when the key is missing or the
// ceremony expired at now. A SQL DELETE ... RETURNING, a Redis GETDEL or a
// compare-and-delete transaction provides this; a signed cookie alone does
// not, because it can be replayed.
//
// Both methods must honor ctx cancellation and must not retain or return
// slices shared with the caller.
type ChallengeStore interface {
	Put(ctx context.Context, key CeremonyKey, ceremony Ceremony) error
	Consume(ctx context.Context, key CeremonyKey, now time.Time) (Ceremony, error)
}

// MemoryChallengeStore is a bounded, in-process [ChallengeStore] for tests,
// development and single-process servers. Ceremonies do not survive a
// restart and are not shared between replicas. It is safe for concurrent
// use; create it with [NewMemoryChallengeStore].
type MemoryChallengeStore struct {
	// Now is the clock Put uses to discard expired ceremonies when the
	// store is full. Nil means time.Now. Set it, before first use, to the
	// relying party's [Config.Clock], the clock whose time Consume receives,
	// so both agree on what has expired.
	Now func() time.Time

	mu       sync.Mutex
	capacity int
	entries  map[CeremonyKey]Ceremony
}

// NewMemoryChallengeStore returns a store that holds at most capacity
// pending ceremonies (1 to 1,000,000). When full, Put first discards expired
// ceremonies and then fails with [ErrCapacity].
func NewMemoryChallengeStore(capacity int) (*MemoryChallengeStore, error) {
	if capacity < 1 || capacity > 1_000_000 {
		return nil, ErrInvalidInput
	}
	return &MemoryChallengeStore{capacity: capacity, entries: make(map[CeremonyKey]Ceremony)}, nil
}

// Put stores a copy of ceremony under key. It fails with [ErrChallenge] if
// key is present and with [ErrCapacity] when the store is full.
func (s *MemoryChallengeStore) Put(ctx context.Context, key CeremonyKey, ceremony Ceremony) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[key]; exists {
		return ErrChallenge
	}
	if len(s.entries) >= s.capacity {
		clock := time.Now
		if s.Now != nil {
			clock = s.Now
		}
		now := clock()
		for k, c := range s.entries {
			if !now.Before(c.Expires) {
				delete(s.entries, k)
			}
		}
		if len(s.entries) >= s.capacity {
			return ErrCapacity
		}
	}
	s.entries[key] = ceremony.clone()
	return nil
}

// Consume atomically removes and returns the ceremony under key. A missing
// or expired ceremony fails with [ErrChallenge]; an expired one is removed.
func (s *MemoryChallengeStore) Consume(ctx context.Context, key CeremonyKey, now time.Time) (Ceremony, error) {
	if err := ctx.Err(); err != nil {
		return Ceremony{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ceremony, ok := s.entries[key]
	if !ok {
		return Ceremony{}, ErrChallenge
	}
	delete(s.entries, key)
	if !now.Before(ceremony.Expires) {
		return Ceremony{}, ErrChallenge
	}
	return ceremony.clone(), nil
}

// Len reports the number of stored ceremonies, including expired ones not
// yet discarded.
func (s *MemoryChallengeStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
