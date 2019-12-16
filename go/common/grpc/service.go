package grpc

import "fmt"

// ServicePrefix is a prefix given to all gRPC services defined by oasis-core.
const ServicePrefix = "oasis-core."

// ServiceName is a gRPC service name.
type ServiceName string

// NewServiceName creates a new gRPC service name.
func NewServiceName(name string) ServiceName {
	return ServiceName(ServicePrefix + name)
}

// NewMethodName creates a new method name for the given service.
func (sn ServiceName) NewMethodName(name string) *MethodName {
	return &MethodName{
		short: name,
		full:  fmt.Sprintf("/%s/%s", sn, name),
	}
}

// MethodName is a gRPC method name.
type MethodName struct {
	short string
	full  string
}

// Short returns the short method name.
func (m *MethodName) Short() string {
	return m.short
}

// Full returns the full method name.
func (m *MethodName) Full() string {
	return m.full
}
