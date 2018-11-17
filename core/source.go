package core

import "context"

type Source interface {
	Query(context.Context, Domain, Type) (*Response, error)
}
