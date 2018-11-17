package core

import "context"

// Source defines the minimal interface for a DoH resolver.
type Source interface {
	Query(context.Context, Domain, Type) (*Response, error)
	String() string
}
