package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tmApi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmcrypto "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	nodeCmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
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

type nodeStats struct {
	elections  int64
	signatures int64
	selections int64
	proposals  int64
}

// entityStats are per entity stats.
type entityStats struct {
	id    signature.PublicKey
	nodes map[signature.PublicKey]*nodeStats
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

// printEntityAvailability prints topN entities by availability score.
func (s stats) printEntityAvailability(topN int) {
	type results struct {
		entityID          signature.PublicKey
		elections         int64
		signatures        int64
		selections        int64
		proposals         int64
		nodes             int
		availabilityScore int64
	}
	res := []results{}

	// Compute per entity stats.
	for eID, eStats := range s.entities {
		entity := results{entityID: eID, nodes: len(eStats.nodes)}
		for _, ns := range eStats.nodes {
			entity.elections += ns.elections
			entity.signatures += ns.signatures
			entity.selections += ns.selections
			entity.proposals += ns.proposals
		}
		entity.availabilityScore = entity.signatures
		if entity.selections > 0 {
			entity.availabilityScore += entity.proposals * entity.elections / entity.selections
		}
		res = append(res, entity)
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].availabilityScore > res[j].availabilityScore
	})

	// Print results.
	written, _ := fmt.Printf("|%-5s|%-64s|%-6s|%13s|%10s|%14s|%9s|%18s|\n", "Rank", "Entity ID", "Nodes", "Had validator", "Signatures", "Times selected", "Proposals", "Availability score")
	fmt.Println(strings.Repeat("-", written-1))
	rank := 0
	tieScore := int64(0)
	for idx, r := range res {
		if idx == 0 || r.availabilityScore != tieScore {
			rank = idx + 1
			tieScore = r.availabilityScore
		}
		fmt.Printf("|%-5d|%-64s|%6d|%13d|%10d|%14d|%9d|%18d|\n", rank, r.entityID, r.nodes, r.elections, r.signatures, r.selections, r.proposals, r.availabilityScore)
	}
}

// nodeExists returns if node with address exists.
func (s stats) nodeExists(nodeAddr string) bool {
	_, ok := s.nodeAddressMap[nodeAddr]
	return ok
}

// getNodeStats gives you a pointer to the nodeStats struct for a node.
func (s stats) getNodeStats(nodeAddr string) (*nodeStats, error) {
	node, ok := s.nodeAddressMap[nodeAddr]
	if !ok {
		return nil, fmt.Errorf("missing node address map, address: %s", nodeAddr)
	}
	entity, ok := s.entities[node.entityID]
	if !ok {
		return nil, fmt.Errorf("missing entity for node, address: %s", nodeAddr)
	}
	ns, ok := entity.nodes[node.nodeID]
	if !ok {
		return nil, fmt.Errorf("missing entity node: %s", nodeAddr)
	}
	return ns, nil
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
	// Fetch nodes.
	nodes, err := registry.GetNodes(ctx, height)
	if err != nil {
		return err
	}

	// Update stored mappings.
	for _, n := range nodes {
		var es *entityStats
		var ok bool
		// Get or create node entity.
		if es, ok = s.entities[n.EntityID]; !ok {
			es = &entityStats{
				id:    n.EntityID,
				nodes: make(map[signature.PublicKey]*nodeStats),
			}
			s.entities[n.EntityID] = es
		}

		// Initialize node stats if missing.
		if _, ok := es.nodes[n.ID]; !ok {
			es.nodes[n.ID] = &nodeStats{}
			cID := n.Consensus.ID
			tmAddr := tmcrypto.PublicKeyToTendermint(&cID).Address().String()
			s.nodeAddressMap[tmAddr] = nodeIDs{
				entityID: n.EntityID,
				nodeID:   n.ID,
			}
		}
	}

	return nil
}

func (s stats) ensureNodeTracking(ctx context.Context, nodeTmAddr string, height int64, registry registryAPI.Backend) error {
	// Check if node is already being tracked.
	if s.nodeExists(nodeTmAddr) {
		return nil
	}

	logger.Debug("missing node tendermint address, querying registry",
		"height", height,
		"addr", nodeTmAddr,
	)

	// Query registry at current height.
	return s.addRegistryData(ctx, registry, height)
}

func (s stats) nodeStatsOrExit(ctx context.Context, registry registryAPI.Backend, height int64, nodeAddr string) *nodeStats {
	if err := s.ensureNodeTracking(ctx, nodeAddr, height, registry); err != nil {
		logger.Error("failed to query registry",
			"err", err,
			"height", height,
		)
		os.Exit(1)
	}

	ns, err := s.getNodeStats(nodeAddr)
	if err != nil {
		logger.Error("node stats absent",
			"err", err,
		)
		os.Exit(1)
	}
	return ns
}

func getTmBlockMetaOrExit(ctx context.Context, consensus consensusAPI.ClientBackend, height int64) tmApi.BlockMeta {
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
	return tmBlockMeta
}

// getStats queries node for entity stats between 'start' and 'end' block heights.
func getStats(ctx context.Context, consensus consensusAPI.ClientBackend, registry registryAPI.Backend, start, end int64) *stats {
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

	// Track previous proposer address.
	var previousProposerAddr tmtypes.Address

	// Block traversal.
	for height := start; height <= end; height++ {
		if height%1000 == 0 {
			logger.Debug("querying block",
				"height", height,
			)
		}

		// Get block.
		tmBlockMeta := getTmBlockMetaOrExit(ctx, consensus, height)

		// Process the commit that is put on chain in this block.
		if height > 1 {
			// Commit is for previous height.
			lastCommitHeight := tmBlockMeta.LastCommit.Height

			// Get validators.
			// Hypothesis: this gets the validator set with priorities after they're incremented to get the round 0
			// proposer.
			vs, err := consensus.GetValidatorSet(ctx, lastCommitHeight)
			if err != nil {
				logger.Error("failed to query validators",
					"err", err,
					"height", lastCommitHeight,
				)
				os.Exit(1)
			}
			var protoVals tmproto.ValidatorSet
			if err = protoVals.Unmarshal(vs.Meta); err != nil {
				logger.Error("unmarshal validator set error",
					"meta", vs.Meta,
					"err", err,
					"height", lastCommitHeight,
				)
				os.Exit(1)
			}
			vals, err := tmtypes.ValidatorSetFromProto(&protoVals)
			if err != nil {
				logger.Error("unmarshal validator set error",
					"meta", vs.Meta,
					"err", err,
					"height", lastCommitHeight,
				)
				os.Exit(1)
			}

			// Go over all validators.
			for _, val := range vals.Validators {
				stats.nodeStatsOrExit(ctx, registry, lastCommitHeight, val.Address.String()).elections++
			}

			// Go over all signatures for a block.
			for i, sig := range tmBlockMeta.LastCommit.Signatures {
				valAddr := vals.Validators[i].Address
				if sig.Absent() {
					logger.Debug("skipping absent signature",
						"height", lastCommitHeight,
						"round", tmBlockMeta.LastCommit.Round,
						"addr", valAddr,
					)
					continue
				} else if sig.BlockIDFlag == tmtypes.BlockIDFlagNil {
					logger.Debug("skipping signature for nil",
						"height", lastCommitHeight,
						"round", tmBlockMeta.LastCommit.Round,
						"addr", valAddr,
						"sig_ts", sig.Timestamp,
					)
					continue
				}

				if !bytes.Equal(sig.ValidatorAddress, valAddr) {
					logger.Error("validator address mismatch",
						"height", lastCommitHeight,
						"round", tmBlockMeta.LastCommit.Round,
						"i", i,
						"sigs_addr", sig.ValidatorAddress,
						"vals_addr", valAddr,
					)
					os.Exit(1)
				}

				stats.nodeStatsOrExit(ctx, registry, lastCommitHeight, sig.ValidatorAddress.String()).signatures++
			}

			for i := int32(0); i < tmBlockMeta.LastCommit.Round; i++ {
				// This round selected a validator to propose, but it didn't go through.
				logger.Debug("failed round",
					"height", lastCommitHeight,
					"round", i,
					"selected", vals.Proposer.Address,
				)

				stats.nodeStatsOrExit(ctx, registry, lastCommitHeight, vals.Proposer.Address.String()).selections++

				vals.IncrementProposerPriority(1)
			}

			if previousProposerAddr == nil {
				// Access one block back from the beginning to confirm the correct proposer.
				prevTmBlockMeta := getTmBlockMetaOrExit(ctx, consensus, lastCommitHeight)
				previousProposerAddr = prevTmBlockMeta.Header.ProposerAddress
			}
			if !bytes.Equal(vals.Proposer.Address, previousProposerAddr) {
				logger.Error("reckoned proposer selection didn't match proposer on chain",
					"height", lastCommitHeight,
					"round", tmBlockMeta.LastCommit.Round,
					"reckoned", vals.Proposer.Address,
					"proposer", previousProposerAddr,
				)
				os.Exit(1)
			}

			nsProposer := stats.nodeStatsOrExit(ctx, registry, lastCommitHeight, previousProposerAddr.String())
			nsProposer.selections++
			nsProposer.proposals++
		}

		// Update previous proposer address.
		previousProposerAddr = tmBlockMeta.Header.ProposerAddress
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

	stats.printEntityAvailability(topN)
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
