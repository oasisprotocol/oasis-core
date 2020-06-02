package grpc

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

// ServicePrefix is a prefix given to all gRPC services defined by oasis-core.
const ServicePrefix = "oasis-core."

var registeredMethods sync.Map

// ServiceName is a gRPC service name.
type ServiceName string

// NamespaceExtractorFunc extracts namespce from a method request.
type NamespaceExtractorFunc func(ctx context.Context, req interface{}) (common.Namespace, error)

// AccessControlFunc is a function that decides whether access control policy lookup is required for
// a specific request. In case an error is returned the request is aborted.
type AccessControlFunc func(ctx context.Context, req interface{}) (bool, error)

// ServiceNameFromMethod extract service name from method name.
func ServiceNameFromMethod(methodName string) ServiceName {
	substrs := strings.Split(methodName, "/")
	return ServiceName(substrs[1])
}

// NewServiceName creates a new gRPC service name.
func NewServiceName(name string) ServiceName {
	if strings.Contains(name, "/") {
		panic(fmt.Errorf("'/' not allowed in service name: %s", name))
	}
	return ServiceName(ServicePrefix + name)
}

// GetRegisteredMethod returns a registered method description.
func GetRegisteredMethod(name string) (*MethodDesc, error) {
	md, ok := registeredMethods.Load(name)
	if !ok {
		return nil, fmt.Errorf("method not registered")
	}
	m, ok := md.(*MethodDesc)
	if !ok {
		panic(fmt.Errorf("unexpected method description type: %T", md))
	}
	return m, nil
}

// NewMethod creates a new method name for the given service.
func (sn ServiceName) NewMethod(name string, requestType interface{}) *MethodDesc {
	if strings.Contains(name, "/") {
		panic(fmt.Errorf("'/' not allowed in method name: %s", name))
	}

	md := &MethodDesc{
		short:       name,
		full:        fmt.Sprintf("/%s/%s", sn, name),
		requestType: requestType,
	}

	if _, isRegistered := registeredMethods.Load(md.FullName()); isRegistered {
		panic(fmt.Errorf("service: method already registered: %s", name))
	}
	registeredMethods.Store(md.FullName(), md)

	return md
}

// WithNamespaceExtractor tells weather the endpoint does have namespace
// extractor defined.
func (m *MethodDesc) WithNamespaceExtractor(f NamespaceExtractorFunc) *MethodDesc {
	m.namespaceExtractor = f
	return m
}

// WithAccessControl tells weather the endpoint does have access control.
func (m *MethodDesc) WithAccessControl(f AccessControlFunc) *MethodDesc {
	m.accessControl = f
	return m
}

// MethodDesc is a gRPC method descriptor.
type MethodDesc struct {
	short       string
	full        string
	requestType interface{}

	accessControl      AccessControlFunc
	namespaceExtractor NamespaceExtractorFunc
}

// ShortName returns the short method name.
func (m *MethodDesc) ShortName() string {
	return m.short
}

// FullName returns the full method name.
func (m *MethodDesc) FullName() string {
	return m.full
}

// IsAccessControlled retruns if method is access controlled.
func (m *MethodDesc) IsAccessControlled(ctx context.Context, req interface{}) (bool, error) {
	if m.accessControl == nil {
		return false, nil
	}
	return m.accessControl(ctx, req)
}

// UnmarshalRawMessage unmarshals `cbor.RawMessage` request.
func (m *MethodDesc) UnmarshalRawMessage(req *cbor.RawMessage) (interface{}, error) {
	v := reflect.New(reflect.TypeOf(m.requestType)).Interface()
	if err := cbor.Unmarshal(*req, v); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	return v, nil
}

// HasNamespaceExtractor returns true iff method has a defined namespace
// extractor.
func (m *MethodDesc) HasNamespaceExtractor() bool {
	return m.namespaceExtractor != nil
}

// ExtractNamespace extracts the from the method request.
func (m *MethodDesc) ExtractNamespace(ctx context.Context, req interface{}) (common.Namespace, error) {
	if m.namespaceExtractor == nil {
		return common.Namespace{}, fmt.Errorf("method not namespaced")
	}
	return m.namespaceExtractor(ctx, req)
}
