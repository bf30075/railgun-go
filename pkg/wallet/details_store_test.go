package wallet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
)

func TestWalletDetailsDefaultsUpdatesAndPersists(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	detailsPath := filepath.Join(t.TempDir(), "wallet-details.json")
	detailsStore := NewFileWalletDetailsStore(detailsPath)
	wallet, err := NewWalletWithStoresAndDetails(
		NewMemoryStateStore(),
		railevents.NewMemoryCheckpointStore(),
		testSyncKeys(),
		testBalancePOIManager(),
		nil,
		nil,
		nil,
		detailsStore,
	)
	if err != nil {
		t.Fatal(err)
	}

	details, err := wallet.WalletDetails(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(details.TreeScannedHeights) != 0 || details.CreationTree != nil || details.CreationTreeHeight != nil {
		t.Fatalf("expected default wallet details, got %+v", details)
	}

	if err := wallet.UpdateTreeScannedHeight(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, chain, 2, 99); err != nil {
		t.Fatal(err)
	}
	creationTree := uint64(1)
	creationHeight := uint64(42)
	if err := wallet.SetWalletCreationDetails(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, chain, &creationTree, &creationHeight); err != nil {
		t.Fatal(err)
	}
	details, err = wallet.WalletDetails(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, chain)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, details.TreeScannedHeights, []uint64{0, 0, 99})
	if details.CreationTree == nil || *details.CreationTree != 1 || details.CreationTreeHeight == nil || *details.CreationTreeHeight != 42 {
		t.Fatalf("unexpected creation details %+v", details)
	}

	raw, err := os.ReadFile(detailsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), railcrypto.TXIDVersionV2PoseidonMerkle) || !strings.Contains(string(raw), `"treeScannedHeights"`) {
		t.Fatalf("expected persisted wallet details, got\n%s", raw)
	}

	reopened := NewFileWalletDetailsStore(detailsPath)
	detailsMap, err := reopened.LoadWalletDetailsMap(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	reopenedDetails := detailsMap[railcrypto.TXIDVersionV2PoseidonMerkle]
	assertJSONEqual(t, reopenedDetails.TreeScannedHeights, []uint64{0, 0, 99})
	if reopenedDetails.CreationTree == nil || *reopenedDetails.CreationTree != 1 {
		t.Fatalf("expected persisted creation tree, got %+v", reopenedDetails)
	}
}

func TestMemoryWalletDetailsStoreClonesValues(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	store := NewMemoryWalletDetailsStore()
	details := WalletDetailsMap{
		railcrypto.TXIDVersionV2PoseidonMerkle: {
			TreeScannedHeights: []uint64{1},
		},
	}
	if err := store.SaveWalletDetailsMap(ctx, chain, details); err != nil {
		t.Fatal(err)
	}
	details[railcrypto.TXIDVersionV2PoseidonMerkle] = WalletDetails{TreeScannedHeights: []uint64{999}}

	loaded, err := store.LoadWalletDetailsMap(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	loaded[railcrypto.TXIDVersionV2PoseidonMerkle].TreeScannedHeights[0] = 500
	reloaded, err := store.LoadWalletDetailsMap(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, reloaded[railcrypto.TXIDVersionV2PoseidonMerkle].TreeScannedHeights, []uint64{1})
}
