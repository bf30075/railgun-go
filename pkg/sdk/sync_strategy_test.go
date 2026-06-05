package sdk

import (
	"context"
	"strings"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railquick "github.com/bf30075/railgun-go/pkg/quicksync"
)

func TestBSCV2QuickSyncStrategyImportsThenRunsRPCTailScan(t *testing.T) {
	ctx := context.Background()
	network := testRuntimeNetworkConfig()
	network.Name = "BNB_Chain"
	network.DefaultStartBlock = 100
	quickSyncedBlock := network.DefaultStartBlock + 10
	var quickSyncStart uint64
	provider := &sdkRecordingProvider{latest: quickSyncedBlock + 2}

	runtime, err := NewMemoryRuntimeFromMnemonic(RuntimeOptions{
		Network:  network,
		Provider: provider,
		SyncStrategy: BSCV2QuickSyncStrategy{
			Fetcher: func(_ context.Context, options railquick.V2GraphOptions) (railevents.V2AccumulatedEvents, error) {
				quickSyncStart = options.StartBlock
				return railevents.V2AccumulatedEvents{
					CommitmentEvents: []railevents.CommitmentEvent{{
						Txid:          sdkHex32("04"),
						TreeNumber:    0,
						StartPosition: 0,
						BlockNumber:   quickSyncedBlock,
						Commitments: []railevents.Commitment{{
							Txid:           sdkHex32("04"),
							CommitmentType: railevents.CommitmentTypeTransactV2,
							Hash:           sdkHex32("09"),
							BlockNumber:    quickSyncedBlock,
							UTXOTree:       0,
							UTXOIndex:      0,
						}},
					}},
				}, nil
			},
		},
	}, testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}

	results, err := runtime.Sync(ctx, "sdk-quick")
	if err != nil {
		t.Fatal(err)
	}
	if quickSyncStart != network.DefaultStartBlock {
		t.Fatalf("expected quick-sync start block %d, got %d", network.DefaultStartBlock, quickSyncStart)
	}
	if len(provider.filters) != 1 {
		t.Fatalf("expected one RPC tail scan, got %d", len(provider.filters))
	}
	if provider.filters[0].FromBlock != quickSyncedBlock+1 {
		t.Fatalf("expected RPC tail scan from %d, got %d", quickSyncedBlock+1, provider.filters[0].FromBlock)
	}
	result := results[railcrypto.TXIDVersionV2PoseidonMerkle]
	if !result.Scanned || result.ToBlock != provider.latest || result.Checkpoint.NextBlock != provider.latest+1 {
		t.Fatalf("unexpected sync result %+v", result)
	}
	leaves, err := runtime.engine.stores.UTXOMerkleTree.ListLeaves(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 1 {
		t.Fatalf("expected quick-sync leaf import, got %d leaves", len(leaves))
	}
}

type sdkRecordingProvider struct {
	latest  uint64
	filters []railevents.LogFilter
}

func (provider *sdkRecordingProvider) BlockNumber(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return provider.latest, nil
}

func (provider *sdkRecordingProvider) FilterLogs(ctx context.Context, filter railevents.LogFilter) ([]railevents.ContractLog, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	provider.filters = append(provider.filters, filter)
	return []railevents.ContractLog{}, nil
}

func sdkHex32(suffix string) string {
	return strings.Repeat("0", 64-len(suffix)) + suffix
}
