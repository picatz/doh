package cose

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidInput reports an argument that can never succeed, such as a
	// key that [MarshalPublicKey] cannot encode under the algorithm it was
	// given.
	ErrInvalidInput = errors.New("cose: invalid input")

	// ErrFormat reports encoded data that is not well formed: a COSE_Key that
	// is not canonical CBOR, lacks or repeats a parameter, carries one the
	// key type does not define or private key material, names a key type or
	// curve its algorithm does not use, or holds a point off its curve; or
	// text and JSON that name no algorithm.
	ErrFormat = errors.New("cose: malformed encoding")

	// ErrUnsupported reports a well-formed algorithm, key type or curve that
	// this package does not implement, such as Ed448 or ML-DSA. It matches
	// [errors.ErrUnsupported].
	ErrUnsupported = fmt.Errorf("cose: algorithm, key type or curve: %w", errors.ErrUnsupported)

	// ErrVerification reports a signature that does not verify, including one
	// checked with a key that its algorithm cannot use.
	ErrVerification = errors.New("cose: signature verification failed")
)
