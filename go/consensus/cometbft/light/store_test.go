package light

import (
	"testing"

	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

func TestPrunedStore(t *testing.T) {
	t.Run("Pruning enabled", func(t *testing.T) {
		high := uint16(5)
		low := uint16(2)
		store := newMockStore()
		ps := newPrunedStore(store, high, low)

		// Fill the store.
		for i := range high {
			lb := &cmttypes.LightBlock{
				SignedHeader: &cmttypes.SignedHeader{
					Header: &cmttypes.Header{
						Height: int64(i),
					},
				},
			}
			err := ps.SaveLightBlock(lb)
			require.NoError(t, err)
			require.Equal(t, i+1, ps.Size())
		}

		// Trigger pruning.
		lb := &cmttypes.LightBlock{
			SignedHeader: &cmttypes.SignedHeader{
				Header: &cmttypes.Header{
					Height: int64(high),
				},
			},
		}
		err := ps.SaveLightBlock(lb)
		require.NoError(t, err)
		require.Equal(t, low+1, ps.Size())
	})

	t.Run("Pruning disabled", func(t *testing.T) {
		high := uint16(0)
		low := uint16(0)
		store := newMockStore()
		ps := newPrunedStore(store, high, low)

		// Fill the store.
		for i := range 2 * high {
			lb := &cmttypes.LightBlock{
				SignedHeader: &cmttypes.SignedHeader{
					Header: &cmttypes.Header{
						Height: int64(i),
					},
				},
			}
			err := ps.SaveLightBlock(lb)
			require.NoError(t, err)
			require.Equal(t, i+1, ps.Size())
		}
	})
}

type mockStore struct {
	blocks []*cmttypes.LightBlock
}

func newMockStore() *mockStore {
	return &mockStore{
		blocks: make([]*cmttypes.LightBlock, 0),
	}
}

func (s *mockStore) SaveLightBlock(lb *cmttypes.LightBlock) error {
	s.blocks = append(s.blocks, lb)
	return nil
}

func (s *mockStore) DeleteLightBlock(int64) error {
	panic("not implemented")
}

func (s *mockStore) FirstLightBlockHeight() (int64, error) {
	panic("not implemented")
}

func (s *mockStore) LastLightBlockHeight() (int64, error) {
	panic("not implemented")
}

func (s *mockStore) LightBlock(int64) (*cmttypes.LightBlock, error) {
	panic("not implemented")
}

func (s *mockStore) LightBlockBefore(int64) (*cmttypes.LightBlock, error) {
	panic("not implemented")
}

func (s *mockStore) Size() uint16 {
	return uint16(len(s.blocks))
}

func (s *mockStore) Prune(size uint16) error {
	n := max(0, len(s.blocks)-int(size))
	s.blocks = s.blocks[n:]
	return nil
}
