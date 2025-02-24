package secrets

import (
	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

var (
	// deprecatedServiceName is the deprecated gRPC service name.
	deprecatedServiceName = cmnGrpc.NewServiceName("KeyManager")

	// deprecatedStateToGenesis is the deprecated StateToGenesis method.
	deprecatedStateToGenesis = deprecatedServiceName.NewMethod("StateToGenesis", int64(0))
	// deprecatedGetStatus is the deprecated GetStatus method.
	deprecatedGetStatus = deprecatedServiceName.NewMethod("GetStatus", registry.NamespaceQuery{})
	// deprecatedGetStatuses is the deprecated GetStatuses method.
	deprecatedGetStatuses = deprecatedServiceName.NewMethod("GetStatuses", int64(0))
	// deprecatedGetMasterSecret is the deprecated GetMasterSecret method.
	deprecatedGetMasterSecret = deprecatedServiceName.NewMethod("GetMasterSecret", registry.NamespaceQuery{})
	// deprecatedGetEphemeralSecret is the deprecated GetEphemeralSecret method.
	deprecatedGetEphemeralSecret = deprecatedServiceName.NewMethod("GetEphemeralSecret", registry.NamespaceQuery{})

	// deprecatedWatchStatuses is the WatchStatuses method.
	deprecatedWatchStatuses = deprecatedServiceName.NewMethod("WatchStatuses", nil)
	// deprecatedWatchMasterSecrets is the deprecated WatchMasterSecrets method.
	deprecatedWatchMasterSecrets = deprecatedServiceName.NewMethod("WatchMasterSecrets", nil)
	// deprecatedWatchEphemeralSecrets is the deprecated WatchEphemeralSecrets method.
	deprecatedWatchEphemeralSecrets = deprecatedServiceName.NewMethod("WatchEphemeralSecrets", nil)

	// deprecatedServiceDesc is the deprecated gRPC service descriptor.
	deprecatedServiceDesc = grpc.ServiceDesc{
		ServiceName: string(deprecatedServiceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: deprecatedStateToGenesis.ShortName(),
				Handler:    handlerStateToGenesis,
			},
			{
				MethodName: deprecatedGetStatus.ShortName(),
				Handler:    handlerGetStatus,
			},
			{
				MethodName: deprecatedGetStatuses.ShortName(),
				Handler:    handlerGetStatuses,
			},
			{
				MethodName: deprecatedGetMasterSecret.ShortName(),
				Handler:    handlerGetMasterSecret,
			},
			{
				MethodName: deprecatedGetEphemeralSecret.ShortName(),
				Handler:    handlerGetEphemeralSecret,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    deprecatedWatchStatuses.ShortName(),
				Handler:       handlerWatchStatuses,
				ServerStreams: true,
			},
			{
				StreamName:    deprecatedWatchMasterSecrets.ShortName(),
				Handler:       handlerWatchMasterSecrets,
				ServerStreams: true,
			},
			{
				StreamName:    deprecatedWatchEphemeralSecrets.ShortName(),
				Handler:       handlerWatchEphemeralSecrets,
				ServerStreams: true,
			},
		},
	}
)
