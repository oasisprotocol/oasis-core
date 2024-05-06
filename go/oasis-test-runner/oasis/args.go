package oasis

import (
	"encoding/hex"
	"fmt"
	"strconv"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	commonGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/byzantine"
)

// Argument is a single argument on the commandline, including its values.
type Argument struct {
	// Name is the name of the argument, i.e. the leading dashed component.
	Name string `json:"name"`
	// Values is the array of values passed to this argument.
	Values []string `json:"values"`
	// MultiValued tells the system that multiple occurrences of the same argument
	// should have their value arrays merged.
	MultiValued bool `json:"multi_valued"`
}

type argBuilder struct {
	vec []Argument

	// dontBlameOasis is true, if CfgDebugDontBlameOasis is passed.
	dontBlameOasis bool
}

func (args *argBuilder) clone() *argBuilder {
	vec := make([]Argument, len(args.vec))
	copy(vec[:], args.vec)

	return &argBuilder{
		vec:            vec,
		dontBlameOasis: args.dontBlameOasis,
	}
}

func (args *argBuilder) extraArgs(extra []Argument) *argBuilder {
	args.vec = append(args.vec, extra...)
	return args
}

func (args *argBuilder) internalSocketAddress(path string) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   grpc.CfgAddress,
		Values: []string{"unix:" + path},
	})
	return args
}

func (args *argBuilder) debugDontBlameOasis() *argBuilder {
	if !args.dontBlameOasis {
		args.vec = append(args.vec, Argument{
			Name: flags.CfgDebugDontBlameOasis,
		})
		args.dontBlameOasis = true
	}
	return args
}

func (args *argBuilder) debugAllowTestKeys() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: cmdCommon.CfgDebugAllowTestKeys,
	})
	return args
}

func (args *argBuilder) debugAllowDebugEnclaves() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: cmdCommon.CfgDebugAllowDebugEnclaves,
	})
	return args
}

func (args *argBuilder) debugTCBLaxVerify() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: cmdCommon.CfgDebugTCBLaxVerify,
	})
	return args
}

func (args *argBuilder) grpcServerPort(port uint16) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   grpc.CfgServerPort,
		Values: []string{strconv.Itoa(int(port))},
	})
	return args
}

func (args *argBuilder) grpcWait() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: grpc.CfgWait,
	})
	return args
}

func (args *argBuilder) grpcLogDebug() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: commonGrpc.CfgLogDebug,
	})
	return args
}

func (args *argBuilder) iasDebugMock() *argBuilder {
	args.vec = append(args.vec, Argument{Name: "ias.debug.mock"})
	return args
}

func (args *argBuilder) iasSPID(spid []byte) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   "ias.spid",
		Values: []string{hex.EncodeToString(spid)},
	})
	return args
}

func (args *argBuilder) configureDebugCrashPoints(prob float64) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   crash.CfgDefaultCrashPointProbability,
		Values: []string{fmt.Sprintf("%f", prob)},
	})
	return args
}

func (args *argBuilder) appendDebugTestEntity() *argBuilder {
	args.vec = append(args.vec, Argument{Name: flags.CfgDebugTestEntity})
	return args
}

func (args *argBuilder) appendNetwork(*Network) *argBuilder {
	args = args.grpcLogDebug()
	return args
}

func (args *argBuilder) byzantineFakeSGX() *argBuilder {
	args.vec = append(args.vec, Argument{Name: byzantine.CfgFakeSGX})
	return args
}

func (args *argBuilder) byzantineVersionFakeEnclaveID(rt *Runtime) *argBuilder {
	eid := rt.GetEnclaveIdentity(0)
	args.vec = append(args.vec, Argument{
		Name:   byzantine.CfgVersionFakeEnclaveID,
		Values: []string{eid.String()},
	})
	return args
}

func (args *argBuilder) byzantineActivationEpoch(epoch beacon.EpochTime) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   byzantine.CfgActivationEpoch,
		Values: []string{strconv.FormatUint(uint64(epoch), 10)},
	})
	return args
}

func (args *argBuilder) byzantineRuntimeID(runtimeID common.Namespace) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   byzantine.CfgRuntimeID,
		Values: []string{runtimeID.String()},
	})
	return args
}

func (args *argBuilder) merge(string) []string {
	output := []string{}
	shipped := map[string][]string{}
	multiValued := map[string][][]string{}

	slicesEqual := func(s1, s2 []string) bool {
		if len(s1) != len(s2) {
			return false
		}
		for i := range s1 {
			if s1[i] != s2[i] {
				return false
			}
		}
		return true
	}

	for _, arg := range args.vec {
		if arg.MultiValued {
			ok := true
			for _, el := range multiValued[arg.Name] {
				if slicesEqual(el, arg.Values) {
					ok = false
					break
				}
			}
			if ok {
				output = append(output, "--"+arg.Name)
				output = append(output, arg.Values...)
				multiValued[arg.Name] = append(multiValued[arg.Name], arg.Values)
			}
		} else {
			vals, ok := shipped[arg.Name]
			if !ok {
				output = append(output, "--"+arg.Name)
				output = append(output, arg.Values...)
				shipped[arg.Name] = arg.Values
			} else {
				if !slicesEqual(vals, arg.Values) {
					panic(fmt.Sprintf("args: single-valued argument given multiple times with different values (%s)", arg.Name))
				}
			}
		}
	}
	return output
}

func newArgBuilder() *argBuilder {
	return &argBuilder{}
}
