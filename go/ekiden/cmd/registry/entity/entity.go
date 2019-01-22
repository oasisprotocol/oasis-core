// Package entity implements the entity registry sub-commands.
package entity

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	grpcRegistry "github.com/oasislabs/ekiden/go/grpc/registry"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

const cmdRegister = "register"

var (
	entityCmd = &cobra.Command{
		Use:   "entity",
		Short: "entity registry backend utilities",
	}

	initCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize an entity",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdFlags.RegisterForce(cmd)
		},
		Run: doInit,
	}

	registerCmd = &cobra.Command{
		Use:   cmdRegister,
		Short: "register an entity",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdFlags.RegisterRetries(cmd)
			cmdGrpc.RegisterClientFlags(cmd, false)
		},
		Run: doRegisterOrDeregister,
	}

	deregisterCmd = &cobra.Command{
		Use:   "deregister",
		Short: "deregister an entity",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdFlags.RegisterRetries(cmd)
			cmdGrpc.RegisterClientFlags(cmd, false)
		},
		Run: doRegisterOrDeregister,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list registered entities",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdGrpc.RegisterClientFlags(cmd, false)
			cmdFlags.RegisterVerbose(cmd)
		},
		Run: doList,
	}

	logger = logging.GetLogger("cmd/registry/entity")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, grpcRegistry.EntityRegistryClient) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := grpcRegistry.NewEntityRegistryClient(conn)

	return conn, client
}

func doInit(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir, err := cmdCommon.DataDirOrPwd()
	if err != nil {
		logger.Error("failed to query data directory",
			"err", err,
		)
		os.Exit(1)
	}

	// Loosely check to see if there is an existing entity.  This isn't
	// perfect, just "oopsie" avoidance.
	if _, _, err = entity.Load(dataDir); err == nil {
		switch cmdFlags.Force() {
		case true:
			logger.Warn("overwriting existing entity")
		default:
			logger.Error("existing entity exists, specifiy --force to overwrite")
			os.Exit(1)
		}
	}

	// Generate a new entity.
	ent, _, err := entity.Generate(dataDir)
	if err != nil {
		logger.Error("failed to generate entity",
			"err", err,
		)
		os.Exit(1)
	}

	logger.Info("generated entity",
		"entity", ent.ID,
	)
}

func doRegisterOrDeregister(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir, err := cmdCommon.DataDirOrPwd()
	if err != nil {
		logger.Error("failed to query data directory",
			"err", err,
		)
		os.Exit(1)
	}

	ent, privKey, err := entity.Load(dataDir)
	if err != nil {
		logger.Error("failed to load entity",
			"err", err,
		)
		os.Exit(1)
	}

	nrRetries := cmdFlags.Retries()
	for i := 0; i <= nrRetries; {
		if err = func() error {
			conn, client := doConnect(cmd)
			defer conn.Close()

			var actErr error
			switch cmd.Use == cmdRegister {
			case true:
				actErr = doRegister(client, ent, privKey)
			case false:
				actErr = doDeregister(client, ent, privKey)
			}
			return actErr
		}(); err == nil {
			return
		}

		if nrRetries > 0 {
			i++
		}
		if i <= nrRetries {
			time.Sleep(1 * time.Second)
		}
	}

	os.Exit(1)
}

func doRegister(client grpcRegistry.EntityRegistryClient, ent *entity.Entity, privKey *signature.PrivateKey) error {
	ent.RegistrationTime = uint64(time.Now().Unix())
	signed, err := entity.SignEntity(*privKey, registry.RegisterEntitySignatureContext, ent)
	if err != nil {
		logger.Error("failed to sign entity",
			"err", err,
		)
		return err
	}

	req := &grpcRegistry.RegisterRequest{
		Entity: signed.ToProto(),
	}
	if _, err = client.RegisterEntity(context.Background(), req); err != nil {
		logger.Error("failed to register entity",
			"err", err,
		)
		return err
	}

	logger.Info("registered entity",
		"entity", privKey.Public(),
	)

	return nil
}

func doDeregister(client grpcRegistry.EntityRegistryClient, ent *entity.Entity, privKey *signature.PrivateKey) error {
	ts := registry.Timestamp(time.Now().Unix())
	signed, err := signature.SignSigned(*privKey, registry.DeregisterEntitySignatureContext, &ts)
	if err != nil {
		logger.Error("failed to sign deregistration",
			"err", err,
		)
		return err
	}

	req := &grpcRegistry.DeregisterRequest{
		Timestamp: signed.ToProto(),
	}
	if _, err = client.DeregisterEntity(context.Background(), req); err != nil {
		logger.Error("failed to deregister entity",
			"err", err,
		)
		return err
	}

	logger.Info("deregistered entity",
		"entity", privKey.Public(),
	)

	return nil
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	entities, err := client.GetEntities(context.Background(), &grpcRegistry.EntitiesRequest{})
	if err != nil {
		logger.Error("failed to query entities",
			"err", err,
		)
		os.Exit(1)
	}

	for _, v := range entities.GetEntity() {
		var ent entity.Entity
		if err = ent.FromProto(v); err != nil {
			logger.Error("failed to de-serialize entity",
				"err", err,
				"pb", v,
			)
			continue
		}

		var s string
		switch cmdFlags.Verbose() {
		case true:
			s = string(json.Marshal(&ent))
		default:
			s = ent.ID.String()
		}

		fmt.Printf("%v\n", s)
	}
}

// Register registers the entity sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		initCmd,
		registerCmd,
		deregisterCmd,
		listCmd,
	} {
		entityCmd.AddCommand(v)
	}

	cmdFlags.RegisterForce(initCmd)
	cmdFlags.RegisterRetries(registerCmd)
	cmdFlags.RegisterRetries(deregisterCmd)
	cmdFlags.RegisterVerbose(listCmd)

	for _, v := range []*cobra.Command{
		registerCmd,
		deregisterCmd,
		listCmd,
	} {
		cmdGrpc.RegisterClientFlags(v, false)
	}

	parentCmd.AddCommand(entityCmd)
}
