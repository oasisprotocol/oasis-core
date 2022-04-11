package control

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	schedulerAPI "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

type stats struct {
	// Rounds.
	rounds uint64
	// Successful rounds.
	successfulRounds uint64
	// Failed rounds.
	failedRounds uint64
	// Rounds failed due to proposer timeouts.
	proposerTimeoutedRounds uint64
	// Epoch transition rounds.
	epochTransitionRounds uint64
	// Suspended rounds.
	suspendedRounds uint64

	// Discrepancies.
	discrepancyDetected        uint64
	discrepancyDetectedTimeout uint64

	// Per-entity stats.
	entities map[signature.PublicKey]*entityStats

	entitiesOutput [][]string
	entitiesHeader []string
}

type entityStats struct {
	// Rounds entity node was elected.
	roundsElected uint64
	// Rounds entity node was elected as primary executor worker.
	roundsPrimary uint64
	// Rounds entity node was elected as primary executor worker and workers were invoked.
	roundsPrimaryRequired uint64
	// Rounds entity node was elected as a backup executor worker.
	roundsBackup uint64
	// Rounds entity node was elected as a backup executor worker
	// and backup workers were invoked.
	roundsBackupRequired uint64
	// Rounds entity node was a proposer.
	roundsProposer uint64

	// How many times entity node proposed a timeout.
	proposedTimeout uint64

	// How many good blocks committed while being primary worker.
	committeedGoodBlocksPrimary uint64
	// How many bad blocs committed while being primary worker.
	committeedBadBlocksPrimary uint64
	// How many good blocks committed while being backup worker.
	committeedGoodBlocksBackup uint64
	// How many bad blocks committed while being backup worker.
	committeedBadBlocksBackup uint64

	// How many rounds missed committing a block while being a primary worker.
	missedPrimary uint64
	// How many rounds missed committing a block while being a backup worker (and discrepancy detection was invoked).
	missedBackup uint64
	// How many rounds proposer timeout was triggered while being the proposer.
	missedProposer uint64
}

func (s *stats) prepareEntitiesOutput() {
	s.entitiesOutput = make([][]string, 0)

	s.entitiesHeader = []string{
		"Entity ID",
		"Elected",
		"Primary",
		"Backup",
		"Proposer",
		"Primary invoked",
		"Primary Good commit",
		"Prim Bad commmit",
		"Bckp invoked",
		"Bckp Good commit",
		"Bckp Bad commit",
		"Primary missed",
		"Bckp missed",
		"Proposer missed",
		"Proposed timeout",
	}

	for entity, stats := range s.entities {
		var line []string
		line = append(line,
			entity.String(),
			strconv.FormatUint(stats.roundsElected, 10),
			strconv.FormatUint(stats.roundsPrimary, 10),
			strconv.FormatUint(stats.roundsBackup, 10),
			strconv.FormatUint(stats.roundsProposer, 10),
			strconv.FormatUint(stats.roundsPrimaryRequired, 10),
			strconv.FormatUint(stats.committeedGoodBlocksPrimary, 10),
			strconv.FormatUint(stats.committeedBadBlocksPrimary, 10),
			strconv.FormatUint(stats.roundsBackupRequired, 10),
			strconv.FormatUint(stats.committeedGoodBlocksBackup, 10),
			strconv.FormatUint(stats.committeedBadBlocksBackup, 10),
			strconv.FormatUint(stats.missedPrimary, 10),
			strconv.FormatUint(stats.missedBackup, 10),
			strconv.FormatUint(stats.missedProposer, 10),
			strconv.FormatUint(stats.proposedTimeout, 10),
		)
		s.entitiesOutput = append(s.entitiesOutput, line)
	}
}

func (s *stats) printStats() {
	fmt.Printf("Runtime rounds: %d\n", s.rounds)
	fmt.Printf("Successful rounds: %d\n", s.successfulRounds)
	fmt.Printf("Epoch transition rounds: %d\n", s.epochTransitionRounds)
	fmt.Printf("Proposer timeouted rounds: %d\n", s.proposerTimeoutedRounds)
	fmt.Printf("Failed rounds: %d\n", s.failedRounds)
	fmt.Printf("Discrepancies: %d\n", s.discrepancyDetected)
	fmt.Printf("Discrepancies (timeout): %d\n", s.discrepancyDetectedTimeout)
	fmt.Printf("Suspended: %d\n", s.suspendedRounds)

	fmt.Println("Entity stats")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.SetHeader(s.entitiesHeader)
	table.AppendBulk(s.entitiesOutput)
	table.Render()
}

func doRuntimeStats(cmd *cobra.Command, args []string) { //nolint:gocyclo
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	ctx := context.Background()

	// Parse command line arguments
	argLen := len(args)
	if argLen == 0 || argLen > 3 {
		logger.Error("invalid number of arguments")
		os.Exit(1)
	}

	var (
		runtimeID common.Namespace

		startHeight uint64
		endHeight   uint64
	)
	if err := runtimeID.UnmarshalText([]byte(args[0])); err != nil {
		logger.Error("malformed runtime ID",
			"err", err,
			"arg", args[0],
		)
		os.Exit(1)
	}
	if argLen > 1 {
		var err error

		// Start height is present for 2 and 3 args.
		if startHeight, err = strconv.ParseUint(args[1], 10, 64); err != nil {
			logger.Error("malformed start height",
				"err", err,
				"arg", args[1],
			)
			os.Exit(1)
		}

		if argLen == 3 {
			// End height provided.
			if endHeight, err = strconv.ParseUint(args[2], 10, 64); err != nil {
				logger.Error("malformed end height",
					"err", err,
					"arg", args[2],
				)
				os.Exit(1)
			}
		}
	}

	// Connect to the node
	conn, _ := doConnectOnly(cmd)
	consensus := consensusAPI.NewConsensusClient(conn)

	// Fixup the start/end heights if they were not specified (or are 0)
	if startHeight == 0 {
		status, err := consensus.GetStatus(ctx)
		if err != nil {
			logger.Error("failed to query consensus status",
				"err", err,
			)
			os.Exit(1)
		}
		startHeight = uint64(status.LastRetainedHeight)
	}
	if endHeight == 0 {
		blk, err := consensus.GetBlock(ctx, consensusAPI.HeightLatest)
		if err != nil {
			logger.Error("failed to get latest block",
				"err", err,
			)
			os.Exit(1)
		}
		endHeight = uint64(blk.Height)
	}

	chainCtx, err := consensus.GetChainContext(ctx)
	if err != nil {
		logger.Error("failed to get chain context",
			"err", err,
		)
		os.Exit(1)
	}
	signature.SetChainContext(chainCtx)

	logger.Info("gathering statistics",
		"rumtime_id", runtimeID,
		"start_height", startHeight,
		"end_height", endHeight,
	)

	// Do the actual work
	stats := &stats{
		entities: make(map[signature.PublicKey]*entityStats),
	}

	var (
		currentRound     uint64
		currentCommittee *schedulerAPI.Committee
		currentScheduler *schedulerAPI.CommitteeNode
		roundDiscrepancy bool
	)

	roothash := roothashAPI.NewRootHashClient(conn)
	reg := registryAPI.NewRegistryClient(conn)
	nodeToEntity := make(map[signature.PublicKey]signature.PublicKey)

	for height := int64(startHeight); height < int64(endHeight); height++ {
		if height%1000 == 0 {
			logger.Debug("progressed",
				"height", height,
			)
		}
		// Update node to entity map.
		var nodes []*node.Node
		if nodes, err = reg.GetNodes(ctx, height); err != nil {
			logger.Error("failed to get nodes",
				"err", err,
				"height", height,
			)
			os.Exit(1)
		}
		for _, node := range nodes {
			nodeToEntity[node.ID] = node.EntityID
		}

		// Query latest roothash block and events.
		var blk *block.Block
		blk, err = roothash.GetLatestBlock(ctx, &roothashAPI.RuntimeRequest{RuntimeID: runtimeID, Height: height})
		switch err {
		case nil:
		case roothashAPI.ErrInvalidRuntime:
			continue
		default:
			logger.Error("failed to get roothash block",
				"err", err,
				"height", height,
			)
			os.Exit(1)
		}
		var evs []*roothashAPI.Event
		if evs, err = roothash.GetEvents(ctx, height); err != nil {
			logger.Error("failed to get roothash events",
				"err", err,
				"height", height,
			)
			os.Exit(1)
		}

		var proposerTimeout bool
		if currentRound != blk.Header.Round && currentCommittee != nil {
			// If new round, check for proposer timeout.
			// Need to look at submitted transactions if round failure was caused by a proposer timeout.
			var rsp *consensusAPI.TransactionsWithResults
			if rsp, err = consensus.GetTransactionsWithResults(ctx, height); err != nil {
				logger.Error("failed to get transactions",
					"err", err,
					"height", height,
				)
				os.Exit(1)
			}
			for i := 0; i < len(rsp.Transactions); i++ {
				// Ignore failed txs.
				if !rsp.Results[i].IsSuccess() {
					continue
				}
				var sigTx transaction.SignedTransaction
				if err = cbor.Unmarshal(rsp.Transactions[i], &sigTx); err != nil {
					cmdCommon.EarlyLogAndExit(err)
				}
				var tx transaction.Transaction
				if err = sigTx.Open(&tx); err != nil {
					cmdCommon.EarlyLogAndExit(err)
				}
				// Ignore non proposer timeout txs.
				if tx.Method != roothashAPI.MethodExecutorProposerTimeout {
					continue
				}
				var xc roothashAPI.ExecutorProposerTimeoutRequest
				if err = cbor.Unmarshal(tx.Body, &xc); err != nil {
					cmdCommon.EarlyLogAndExit(err)
				}
				// Ignore txs of other runtimes.
				if xc.ID != runtimeID {
					continue
				}
				// Proposer timeout triggered the round failure, update stats.
				stats.entities[nodeToEntity[sigTx.Signature.PublicKey]].proposedTimeout++
				stats.entities[nodeToEntity[currentScheduler.PublicKey]].missedProposer++
				proposerTimeout = true
				break
			}
		}

		// Go over events before updating potential new round committee info.
		// Even if round transition happened at this height, all events emitted
		// at this height belong to the previous round.
		for _, ev := range evs {
			// Skip events for initial height where we don't have round info yet.
			if height == int64(startHeight) {
				break
			}
			// Skip events for other runtimes.
			if ev.RuntimeID != runtimeID {
				continue
			}
			switch {
			case ev.ExecutorCommitted != nil:
				// Nothing to do here. We use Finalized event Good/Bad Compute node
				// fields to process commitments.
			case ev.ExecutionDiscrepancyDetected != nil:
				if ev.ExecutionDiscrepancyDetected.Timeout {
					stats.discrepancyDetectedTimeout++
				} else {
					stats.discrepancyDetected++
				}
				roundDiscrepancy = true
			case ev.Finalized != nil:
				var rtResults *roothashAPI.RoundResults
				if rtResults, err = roothash.GetLastRoundResults(ctx, &roothashAPI.RuntimeRequest{RuntimeID: runtimeID, Height: height}); err != nil {
					logger.Error("failed to get last round results",
						"err", err,
						"height", height,
					)
					os.Exit(1)
				}

				// Skip the empty finalized event that is triggered on initial round.
				if len(rtResults.GoodComputeEntities) == 0 && len(rtResults.BadComputeEntities) == 0 && currentCommittee == nil {
					continue
				}
				// Skip if epoch transition or suspended blocks.
				if blk.Header.HeaderType == block.EpochTransition || blk.Header.HeaderType == block.Suspended {
					continue
				}
				// Skip if proposer timeout.
				if proposerTimeout {
					continue
				}

				// Update stats.
			OUTER:
				for _, member := range currentCommittee.Members {
					entity := nodeToEntity[member.PublicKey]
					// Primary workers are always required.
					if member.Role == schedulerAPI.RoleWorker {
						stats.entities[entity].roundsPrimaryRequired++
					}
					// In case of discrepancies backup workers were invoked as well.
					if roundDiscrepancy && member.Role == schedulerAPI.RoleBackupWorker {
						stats.entities[entity].roundsBackupRequired++
					}

					// Go over good commitments.
					for _, v := range rtResults.GoodComputeEntities {
						if entity != v {
							continue
						}
						switch member.Role {
						case schedulerAPI.RoleWorker:
							stats.entities[entity].committeedGoodBlocksPrimary++
							continue OUTER
						case schedulerAPI.RoleBackupWorker:
							if roundDiscrepancy {
								stats.entities[entity].committeedGoodBlocksBackup++
								continue OUTER
							}
						}
					}

					// Go over bad commitments.
					for _, v := range rtResults.BadComputeEntities {
						if entity != v {
							continue
						}
						switch member.Role {
						case schedulerAPI.RoleWorker:
							stats.entities[entity].committeedBadBlocksPrimary++
							continue OUTER
						case schedulerAPI.RoleBackupWorker:
							if roundDiscrepancy {
								stats.entities[entity].committeedBadBlocksBackup++
								continue OUTER
							}

						}
					}

					// Neither good nor bad - missed commitment.
					if member.Role == schedulerAPI.RoleWorker {
						stats.entities[entity].missedPrimary++
					}
					if roundDiscrepancy && member.Role == schedulerAPI.RoleBackupWorker {
						stats.entities[entity].missedBackup++
					}
				}
			}
		}

		// New round.
		if currentRound != blk.Header.Round {
			currentRound = blk.Header.Round
			stats.rounds++

			switch blk.Header.HeaderType {
			case block.Normal:
				stats.successfulRounds++
			case block.EpochTransition:
				stats.epochTransitionRounds++
			case block.RoundFailed:
				if proposerTimeout {
					stats.proposerTimeoutedRounds++
				} else {
					stats.failedRounds++
				}
			case block.Suspended:
				stats.suspendedRounds++
				currentCommittee = nil
				currentScheduler = nil
				continue
			default:
				logger.Error("unexpected block header type",
					"header_type", blk.Header.HeaderType,
					"height", height,
				)
				os.Exit(1)
			}

			// Query runtime state and setup committee info for the round.
			var state *roothashAPI.RuntimeState
			if state, err = roothash.GetRuntimeState(ctx, &roothashAPI.RuntimeRequest{RuntimeID: runtimeID, Height: height}); err != nil {
				logger.Error("failed to query runtime state",
					"err", err,
					"height", height,
				)
				os.Exit(1)
			}
			if state.ExecutorPool == nil {
				// No committee - election failed(?)
				logger.Warn("unexpected missing committee for runtime",
					"height", height,
				)
				currentCommittee = nil
				currentScheduler = nil
				continue
			}
			// Set committee info.
			currentCommittee = state.ExecutorPool.Committee
			currentScheduler, err = commitment.GetTransactionScheduler(currentCommittee, currentRound)
			if err != nil {
				logger.Error("failed to query transaction scheduler",
					"err", err,
					"height", height,
				)
				os.Exit(1)
			}
			roundDiscrepancy = false

			// Update election stats.
			seen := make(map[signature.PublicKey]bool)
			for _, member := range currentCommittee.Members {
				entity := nodeToEntity[member.PublicKey]
				if _, ok := stats.entities[entity]; !ok {
					stats.entities[entity] = &entityStats{}
				}

				// Multiple records for same node in case the node has
				// multiple roles. Only count it as elected once.
				if !seen[member.PublicKey] {
					stats.entities[entity].roundsElected++
				}
				seen[member.PublicKey] = true

				if member.Role == schedulerAPI.RoleWorker {
					stats.entities[entity].roundsPrimary++
				}
				if member.Role == schedulerAPI.RoleBackupWorker {
					stats.entities[entity].roundsBackup++
				}
				if member.PublicKey == currentScheduler.PublicKey {
					stats.entities[entity].roundsProposer++
				}
			}
		}
	}

	// Prepare and printout stats.
	stats.prepareEntitiesOutput()
	stats.printStats()

	// Also save entity stats in a csv.
	fout, err := os.Create(fmt.Sprintf("runtime-%s-%d-%d-stats.csv", runtimeID, startHeight, endHeight))
	if err != nil {
		logger.Error("failed to open CSV output file",
			"err", err,
		)
		os.Exit(1)
	}
	defer fout.Close()
	w := csv.NewWriter(fout)
	if err = w.Write(stats.entitiesHeader); err != nil {
		logger.Error("failed to write CSV header",
			"err", err,
		)
		os.Exit(1)
	}
	if err = w.WriteAll(stats.entitiesOutput); err != nil {
		logger.Error("failed to write CSV body",
			"err", err,
		)
		os.Exit(1)
	}
}
