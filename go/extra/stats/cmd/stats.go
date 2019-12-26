package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	consensusAPI "github.com/oasislabs/oasis-core/go/consensus/api"
	tmApi "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	tmcrypto "github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
	nodeCmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	registryAPI "github.com/oasislabs/oasis-core/go/registry/api"
)

const (
	cfgStartBlock = "start-block"
	cfgEndBlock   = "end-block"
	cfgTopN       = "top-n"
)

var (
	printStatsFlags = flag.NewFlagSet("", flag.ContinueOnError)

	printStatsCmd = &cobra.Command{
		Use:   "entity-signatures",
		Short: "prints per entity block signature counts",
		Run:   doPrintStats,
	}

	logger = logging.GetLogger("cmd/stats")
)

// entityStats are per entity stats.
type entityStats struct {
	id             signature.PublicKey
	nodeSignatures map[signature.PublicKey]int64
}

// nodeIDs are node identifiers.
type nodeIDs struct {
	entityID signature.PublicKey
	nodeID   signature.PublicKey
}

// stats are gathered entity stats.
type stats struct {
	// Per entity stats.
	entities map[signature.PublicKey]*entityStats

	// Tendermint stores the validator addresses (which are the truncated SHA-256
	// of the node consensus public keys) in Commit data instead of the actual
	// public keys.
	nodeAddressMap map[string]nodeIDs
}

// printEntitySignatures prints topN entities by block signature counts.
func (s stats) printEntitySignatures(topN int) {
	type results struct {
		entityID   signature.PublicKey
		signatures int64
		nodes      int
	}
	res := []results{}

	// Compute per entity signature counts.
	for eID, eStats := range s.entities {
		entity := results{entityID: eID, nodes: len(eStats.nodeSignatures)}
		for _, signs := range eStats.nodeSignatures {
			entity.signatures += signs
		}
		res = append(res, entity)
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].signatures > res[j].signatures
	})

	// Print results.
	fmt.Printf("|%-5s|%-64s|%-6s|%10s|\n", "Rank", "Entity ID", "Nodes", "Signatures")
	fmt.Println(strings.Repeat("-", 5+64+6+10+5))
	for idx, r := range res {
		fmt.Printf("|%-5d|%-64s|%6d|%10d|\n", idx+1, r.entityID, r.nodes, r.signatures)
	}
}

// nodeExists returns if node with address exists.
func (s stats) nodeExists(nodeAddr string) bool {
	_, ok := s.nodeAddressMap[nodeAddr]
	return ok
}

// addNodeSignature adds node signature.
func (s stats) addNodeSignature(nodeAddr string) error {
	node, ok := s.nodeAddressMap[nodeAddr]
	if !ok {
		return fmt.Errorf("missing node address map, address: %s", nodeAddr)
	}
	entity, ok := s.entities[node.entityID]
	if !ok {
		return fmt.Errorf("missing entity for node, address: %s", nodeAddr)
	}
	_, ok = entity.nodeSignatures[node.nodeID]
	if !ok {
		return fmt.Errorf("missing entity node: %s", nodeAddr)
	}
	entity.nodeSignatures[node.nodeID]++
	return nil
}

// newStats initializes empty stats.
func newStats() *stats {
	b := &stats{
		entities:       make(map[signature.PublicKey]*entityStats),
		nodeAddressMap: make(map[string]nodeIDs),
	}
	return b
}

func (s *stats) addRegistryData(ctx context.Context, registry registryAPI.Backend, height int64) error {
	// Fetch entities.
	entities, err := registry.GetEntities(ctx, height)
	if err != nil {
		return err
	}

	// Fetch nodes.
	nodes, err := registry.GetNodes(ctx, height)
	if err != nil {
		return err
	}

	// Map: nodeID -> Node
	nodesMap := make(map[signature.PublicKey]*node.Node)
	for _, n := range nodes {
		nodesMap[n.ID] = n
	}

	// Store new nodes and entities info.
	for _, ent := range entities {
		var es *entityStats
		var ok bool

		// Since registry data can be fetched at multiple heights, entities might
		// already exist.
		if es, ok = s.entities[ent.ID]; !ok {
			es = &entityStats{
				id:             ent.ID,
				nodeSignatures: make(map[signature.PublicKey]int64),
			}
			s.entities[ent.ID] = es
		}

		for _, nodeID := range ent.Nodes {
			node, ok := nodesMap[nodeID]
			if !ok {
				return fmt.Errorf("entity's node missing: %s", nodeID)
			}

			// Add missing nodes.
			if _, ok := es.nodeSignatures[nodeID]; !ok {
				es.nodeSignatures[nodeID] = 0
				cID := node.Consensus.ID
				tmADdr := tmcrypto.PublicKeyToTendermint(&cID).Address().String()
				s.nodeAddressMap[tmADdr] = nodeIDs{
					entityID: ent.ID,
					nodeID:   nodeID,
				}
			}

		}
	}

	return nil
}

// getStats queries node for entity stats between 'start' and 'end' block heights.
func getStats(ctx context.Context, consensus consensusAPI.ClientBackend, registry registryAPI.Backend, start int64, end int64) *stats {
	// Init stats.
	stats := newStats()

	// If latest block, query for exact block number so it doesn't change during
	// the execution.
	if end == consensusAPI.HeightLatest {
		block, err := consensus.GetBlock(ctx, end)
		if err != nil {
			logger.Error("failed to query block",
				"err", err,
				"height", end,
			)
			os.Exit(1)
		}
		end = block.Height
	}

	// Prepopulate registry state with the state at latest height, to avoid
	// querying it at every height. We only query registry at specific heights
	// in case we encounter missing nodes during block traversal.
	err := stats.addRegistryData(ctx, registry, consensusAPI.HeightLatest)
	if err != nil {
		logger.Error("failed to initialize block signatures",
			"err", err,
			"height", consensusAPI.HeightLatest,
		)
		os.Exit(1)
	}

	// Block traversal.
	for height := start; height <= end; height++ {
		if height%1000 == 0 {
			logger.Debug("querying block",
				"height", height,
			)
		}

		// Get block.
		block, err := consensus.GetBlock(ctx, height)
		if err != nil {
			logger.Error("failed to query block",
				"err", err,
				"height", height,
			)
			os.Exit(1)
		}
		var tmBlockMeta tmApi.BlockMeta
		if err := cbor.Unmarshal(block.Meta, &tmBlockMeta); err != nil {
			logger.Error("unmarshal error",
				"meta", block.Meta,
				"err", err,
			)
			os.Exit(1)
		}

		// Go over all signatures for a block.
		// XXX: In tendermint master (not yet released) the signatures are
		// obtained in LastCommit.Signatures.
		for _, sig := range tmBlockMeta.LastCommit.Precommits {
			nodeTmAddr := sig.ValidatorAddress.String()

			// Check if node is already being tracked.
			if !stats.nodeExists(nodeTmAddr) {
				logger.Debug("missing node tendermint address, querying registry",
					"height", height,
					"addr", nodeTmAddr,
				)

				// Query registry at current height.
				err := stats.addRegistryData(ctx, registry, height)
				if err != nil {
					logger.Error("failed to query registry",
						"err", err,
						"height", height,
					)
					os.Exit(1)
				}
			}

			// Add signatures.
			if err := stats.addNodeSignature(nodeTmAddr); err != nil {
				logger.Error("failure adding signature",
					"err", err,
				)
				os.Exit(1)
			}
		}
	}

	return stats
}

func doPrintStats(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	if err := nodeCmdCommon.Init(); err != nil {
		nodeCmdCommon.EarlyLogAndExit(err)
	}

	// Initialize client connection.
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}
	defer conn.Close()

	// Clients.
	consClient := consensusAPI.NewConsensusClient(conn)
	regClient := registryAPI.NewRegistryClient(conn)

	start := viper.GetInt64(cfgStartBlock)
	end := viper.GetInt64(cfgEndBlock)
	topN := viper.GetInt(cfgTopN)
	// Load stats.
	stats := getStats(ctx, consClient, regClient, start, end)

	stats.printEntitySignatures(topN)
}

// Register stats cmd sub-command and all of it's children.
func RegisterStatsCmd(parentCmd *cobra.Command) {
	printStatsFlags.Int64(cfgStartBlock, 1, "start block")
	printStatsFlags.Int64(cfgEndBlock, consensusAPI.HeightLatest, "end block")
	printStatsFlags.Int(cfgTopN, 50, "top N results that will be printed")
	_ = viper.BindPFlags(printStatsFlags)

	printStatsCmd.Flags().AddFlagSet(printStatsFlags)
	printStatsCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)

	parentCmd.AddCommand(printStatsCmd)
}
