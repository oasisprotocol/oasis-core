package syncer

import "context"

// StatsCollector is a ReadSyncer which collects call statistics.
type StatsCollector struct {
	SyncGetCount         int
	SyncGetPrefixesCount int
	SyncIterateCount     int

	rs ReadSyncer
}

// NewnopReadSyncer creates a new no-op read syncer.
func NewStatsCollector(rs ReadSyncer) *StatsCollector {
	return &StatsCollector{
		rs: rs,
	}
}

func (c *StatsCollector) SyncGet(ctx context.Context, request *GetRequest) (*ProofResponse, error) {
	c.SyncGetCount++
	return c.rs.SyncGet(ctx, request)
}

func (c *StatsCollector) SyncGetPrefixes(ctx context.Context, request *GetPrefixesRequest) (*ProofResponse, error) {
	c.SyncGetPrefixesCount++
	return c.rs.SyncGetPrefixes(ctx, request)
}

func (c *StatsCollector) SyncIterate(ctx context.Context, request *IterateRequest) (*ProofResponse, error) {
	c.SyncIterateCount++
	return c.rs.SyncIterate(ctx, request)
}
