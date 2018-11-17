package core

// Type is an alias for a string.
type Type = string

var (
	// IPv4Type for Query
	IPv4Type = Type("A")

	// IPv6Type for Query
	IPv6Type = Type("AAAA")

	// MailType for Query
	MailType = Type("MX")

	// AnyType for Query
	AnyType = Type("ANY")
)
