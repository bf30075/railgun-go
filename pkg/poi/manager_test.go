package poi

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

const (
	managerMockList    = "test_list"
	managerActiveList  = "activeList1"
	managerActiveList2 = "activeList2"
)

func TestLoadManagerConfigCreatesListsAndLaunchBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "poi-manager.json")
	raw := `{
		"lists": [
			{"key": "gather", "type": "Gather", "name": "Gather", "description": "gather list"},
			{"key": "active", "type": "Active", "name": "Active", "description": "active list"}
		],
		"launchBlocks": [
			{"chain": {"type": 0, "id": 1}, "blockNumber": 12345}
		]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	manager, err := LoadManagerConfig(path, &fakePOINode{required: true, active: true})
	if err != nil {
		t.Fatal(err)
	}
	assertStringSlices(t, manager.GetAllListKeys(), []string{"gather", "active"}, "configured list keys")
	assertStringSlices(t, manager.GetActiveListKeys(), []string{"active"}, "configured active list keys")
	launchBlock, ok := manager.LaunchBlock(railchain.Chain{Type: 0, ID: 1})
	if !ok || launchBlock != 12345 {
		t.Fatalf("expected launch block 12345, got %d ok=%t", launchBlock, ok)
	}
	if !manager.IsActiveForChain(railchain.Chain{Type: 0, ID: 1}) {
		t.Fatal("expected configured manager node to be active")
	}
}

func TestManagerBalanceBucketsMatchTypeScriptPOIRules(t *testing.T) {
	manager := testPOIManager(true)
	change := intPtr(railcrypto.OutputTypeChange)
	transfer := intPtr(railcrypto.OutputTypeTransfer)

	tests := []struct {
		name string
		txo  TXO
		want string
	}{
		{
			name: "missing change",
			txo:  TXO{OutputType: change},
			want: WalletBalanceBucketMissingInternalPOI,
		},
		{
			name: "missing transfer",
			txo:  TXO{OutputType: transfer},
			want: WalletBalanceBucketMissingExternalPOI,
		},
		{
			name: "invalid change",
			txo: TXO{
				POIsPerList:    statusMap(TXOPOIListStatusMissing, TXOPOIListStatusValid),
				CommitmentType: CommitmentTypeTransactV2,
				OutputType:     change,
			},
			want: WalletBalanceBucketMissingInternalPOI,
		},
		{
			name: "submitted",
			txo: TXO{
				POIsPerList:    statusMap(TXOPOIListStatusProofSubmitted, TXOPOIListStatusValid),
				CommitmentType: CommitmentTypeTransactV2,
				OutputType:     change,
			},
			want: WalletBalanceBucketProofSubmitted,
		},
		{
			name: "valid",
			txo: TXO{
				POIsPerList:    statusMap(TXOPOIListStatusValid, TXOPOIListStatusValid),
				CommitmentType: CommitmentTypeTransactV2,
				OutputType:     change,
			},
			want: WalletBalanceBucketSpendable,
		},
		{
			name: "shield pending",
			txo: TXO{
				POIsPerList:    statusMap(TXOPOIListStatusMissing, TXOPOIListStatusValid),
				CommitmentType: CommitmentTypeShield,
				OutputType:     change,
			},
			want: WalletBalanceBucketShieldPending,
		},
		{
			name: "shield blocked",
			txo: TXO{
				POIsPerList:    statusMap(TXOPOIListStatusShieldBlocked, TXOPOIListStatusValid),
				CommitmentType: CommitmentTypeShield,
				OutputType:     change,
			},
			want: WalletBalanceBucketShieldBlocked,
		},
		{
			name: "spent",
			txo: TXO{
				SpendTXID:      "123",
				POIsPerList:    statusMap(TXOPOIListStatusShieldBlocked, TXOPOIListStatusValid),
				CommitmentType: CommitmentTypeShield,
				OutputType:     change,
			},
			want: WalletBalanceBucketSpent,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := manager.GetBalanceBucket(test.txo); got != test.want {
				t.Fatalf("expected bucket %s, got %s", test.want, got)
			}
		})
	}
}

func TestManagerListKeyDecisionsMatchTypeScriptPOIRules(t *testing.T) {
	manager := testPOIManager(true)
	invalidInput := TXO{POIsPerList: statusMap(TXOPOIListStatusMissing, TXOPOIListStatusValid)}
	validInput := TXO{POIsPerList: statusMap(TXOPOIListStatusValid, TXOPOIListStatusValid)}
	submittedSent := SentCommitment{
		Value:       big.NewInt(1),
		POIsPerList: statusMap(TXOPOIListStatusProofSubmitted, TXOPOIListStatusValid),
	}
	submittedUnshield := UnshieldPOIEvent{
		POIsPerList: statusMap(TXOPOIListStatusProofSubmitted, TXOPOIListStatusValid),
	}
	invalidUnshield := UnshieldPOIEvent{
		POIsPerList: statusMap(TXOPOIListStatusMissing, TXOPOIListStatusValid),
	}

	assertStringSlices(t, manager.GetListKeysCanGenerateSpentPOIs(
		[]TXO{invalidInput},
		[]SentCommitment{submittedSent},
		[]UnshieldPOIEvent{invalidUnshield},
		true,
	), []string{managerMockList, managerActiveList}, "legacy spent poi list keys")

	zeroValueSent := submittedSent
	zeroValueSent.Value = big.NewInt(0)
	assertStringSlices(t, manager.GetListKeysCanGenerateSpentPOIs(
		[]TXO{invalidInput},
		[]SentCommitment{zeroValueSent},
		[]UnshieldPOIEvent{submittedUnshield},
		true,
	), []string{managerMockList}, "legacy spent poi list keys with zero-value sent commitment")

	assertStringSlices(t, manager.GetListKeysCanGenerateSpentPOIs(
		[]TXO{invalidInput},
		[]SentCommitment{submittedSent},
		[]UnshieldPOIEvent{submittedUnshield},
		false,
	), []string{}, "nonlegacy list keys without valid input proofs")

	assertStringSlices(t, manager.GetListKeysCanGenerateSpentPOIs(
		[]TXO{validInput},
		[]SentCommitment{submittedSent},
		[]UnshieldPOIEvent{invalidUnshield},
		false,
	), []string{managerActiveList}, "nonlegacy list keys with invalid unshield proof")

	assertStringSlices(t, manager.GetListKeysCanSubmitLegacyTransactEvents([]TXO{
		invalidInput,
		validInput,
	}), []string{managerMockList, managerActiveList}, "legacy transact list keys")
}

func TestManagerRetrieveAndSubmitDelegatesToNode(t *testing.T) {
	node := &fakePOINode{required: true, active: true}
	manager := testPOIManagerWithNode(node)
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}

	if !manager.IsActiveForChain(chain) {
		t.Fatal("expected POI active")
	}
	required, err := manager.IsRequiredForChain(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Fatal("expected POI required")
	}
	buckets, err := manager.GetSpendableBalanceBuckets(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	assertStringSlices(t, buckets, []string{WalletBalanceBucketSpendable}, "required spendable buckets")

	pois, err := manager.RetrievePOIsForBlindedCommitments(ctx, "V2_PoseidonMerkle", chain, []BlindedCommitmentData{
		{BlindedCommitment: "abc", Type: BlindedCommitmentTypeTransact},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pois["abc"][managerActiveList] != TXOPOIListStatusValid {
		t.Fatalf("expected valid POI status, got %+v", pois)
	}
	assertStringSlices(t, node.getPOIsRequest.ListKeys, []string{managerMockList, managerActiveList, managerActiveList2}, "node list keys")

	proofs, err := manager.GetPOIMerkleProofs(ctx, "V2_PoseidonMerkle", chain, managerActiveList, []string{"abc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(proofs) != 1 || proofs[0].Leaf != "abc" {
		t.Fatalf("unexpected proofs %+v", proofs)
	}

	ok, err := manager.ValidatePOIMerkleRoots(ctx, "V2_PoseidonMerkle", chain, managerActiveList, []string{"root"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected valid roots")
	}

	err = manager.SubmitPOI(ctx, SubmitPOIRequest{
		TXIDVersion:              "V2_PoseidonMerkle",
		Chain:                    chain,
		ListKey:                  managerActiveList,
		SnarkProof:               railproof.Proof{},
		POIMerkleRoots:           []string{"root"},
		TxidMerkleRoot:           "txidRoot",
		TxidMerkleRootIndex:      7,
		BlindedCommitmentsOut:    []string{"out"},
		RailgunTxidIfHasUnshield: "0x00",
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.submitPOIRequest.ListKey != managerActiveList || node.submitPOIRequest.TxidMerkleRootIndex != 7 {
		t.Fatalf("unexpected submit POI request %+v", node.submitPOIRequest)
	}

	err = manager.SubmitLegacyTransactProofs(ctx, SubmitLegacyTransactProofsRequest{
		TXIDVersion: "V2_PoseidonMerkle",
		Chain:       chain,
		ListKeys:    []string{managerActiveList},
		LegacyTransactProofDatas: []LegacyTransactProofData{
			{TXIDIndex: "1", BlindedCommitment: "abc"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(node.submitLegacyRequest.ListKeys, []string{managerActiveList}) {
		t.Fatalf("unexpected legacy submit request %+v", node.submitLegacyRequest)
	}
}

func TestManagerRetrieveRejectsTooManyBlindedCommitments(t *testing.T) {
	manager := testPOIManager(true)
	values := make([]BlindedCommitmentData, maxBlindedCommitmentPOIRetrieval+1)
	_, err := manager.RetrievePOIsForBlindedCommitments(context.Background(), "V2_PoseidonMerkle", railchain.Chain{}, values)
	if err == nil {
		t.Fatal("expected too many blinded commitments to fail")
	}
	if err.Error() != "Cannot retrieve POIs for more than 1000 blinded commitments at a time" {
		t.Fatalf("unexpected error %q", err.Error())
	}
}

func TestManagerShouldRetrieveAndGeneratePOIs(t *testing.T) {
	manager := testPOIManager(true)
	valid := statusMapAll(TXOPOIListStatusValid, TXOPOIListStatusValid, TXOPOIListStatusValid)
	missing := statusMapAll(TXOPOIListStatusMissing, TXOPOIListStatusMissing, TXOPOIListStatusValid)
	if manager.ShouldRetrieveTXOPOIs(TXO{BlindedCommitment: "abc", POIsPerList: valid}) {
		t.Fatal("expected valid txo POIs to skip retrieval")
	}
	if !manager.ShouldRetrieveTXOPOIs(TXO{BlindedCommitment: "abc", POIsPerList: missing}) {
		t.Fatal("expected missing txo POIs to retrieve")
	}
	if manager.ShouldRetrieveSentCommitmentPOIs(SentCommitment{BlindedCommitment: "abc", Value: big.NewInt(0), POIsPerList: missing}) {
		t.Fatal("expected zero-value sent commitment to skip retrieval")
	}
	if !manager.ShouldGenerateSpentPOIsSentCommitment(SentCommitment{BlindedCommitment: "abc", Value: big.NewInt(1), POIsPerList: missing}) {
		t.Fatal("expected missing sent commitment POIs to generate")
	}
	if !manager.ShouldGenerateSpentPOIsUnshieldEvent(UnshieldPOIEvent{RailgunTxid: "txid", POIsPerList: missing}) {
		t.Fatal("expected missing unshield POIs to generate")
	}
}

func TestManagerLegacyLaunchBlockRulesMatchTypeScript(t *testing.T) {
	manager := testPOIManager(true)
	chain := railchain.Chain{Type: 0, ID: 1}
	missing := statusMapAll(TXOPOIListStatusMissing, TXOPOIListStatusValid, TXOPOIListStatusValid)
	valid := statusMapAll(TXOPOIListStatusValid, TXOPOIListStatusValid, TXOPOIListStatusValid)

	legacyTXO := TXO{
		POIsPerList:                 missing,
		CommitmentType:              CommitmentTypeTransactV2,
		BlindedCommitment:           "0xabc",
		BlockNumber:                 9,
		TransactCreationRailgunTxid: "0xtxid",
	}
	if !manager.IsLegacyTXO(chain, legacyTXO) {
		t.Fatal("expected txo to be legacy before launch block is configured")
	}
	if !manager.ShouldSubmitLegacyTransactEventsTXO(chain, legacyTXO) {
		t.Fatal("expected legacy transact txo with missing POIs to need submission")
	}

	manager.SetLaunchBlock(chain, 10)
	if !manager.IsLegacyTXO(chain, legacyTXO) {
		t.Fatal("expected txo before launch block to be legacy")
	}
	afterLaunch := legacyTXO
	afterLaunch.BlockNumber = 10
	if manager.IsLegacyTXO(chain, afterLaunch) {
		t.Fatal("expected txo at launch block to be non-legacy")
	}
	if manager.ShouldSubmitLegacyTransactEventsTXO(chain, afterLaunch) {
		t.Fatal("expected non-legacy txo to skip legacy submission")
	}

	alreadyValid := legacyTXO
	alreadyValid.POIsPerList = valid
	if manager.ShouldSubmitLegacyTransactEventsTXO(chain, alreadyValid) {
		t.Fatal("expected txo with all valid POIs to skip legacy submission")
	}
	shield := legacyTXO
	shield.CommitmentType = CommitmentTypeShield
	if manager.ShouldSubmitLegacyTransactEventsTXO(chain, shield) {
		t.Fatal("expected shield commitment to skip legacy transact submission")
	}
	missingRailgunTxid := legacyTXO
	missingRailgunTxid.TransactCreationRailgunTxid = ""
	if manager.ShouldSubmitLegacyTransactEventsTXO(chain, missingRailgunTxid) {
		t.Fatal("expected missing railgun txid to skip legacy submission")
	}
}

type fakePOINode struct {
	required bool
	active   bool

	getPOIsRequest      GetPOIsPerListRequest
	submitPOIRequest    SubmitPOIRequest
	submitLegacyRequest SubmitLegacyTransactProofsRequest
}

func (node *fakePOINode) IsActive(railchain.Chain) bool {
	return node.active
}

func (node *fakePOINode) IsRequired(context.Context, railchain.Chain) (bool, error) {
	return node.required, nil
}

func (node *fakePOINode) GetPOIsPerList(_ context.Context, request GetPOIsPerListRequest) (map[string]POIsPerList, error) {
	node.getPOIsRequest = request
	out := map[string]POIsPerList{}
	for _, commitment := range request.BlindedCommitmentDatas {
		out[commitment.BlindedCommitment] = POIsPerList{}
		for _, listKey := range request.ListKeys {
			out[commitment.BlindedCommitment][listKey] = TXOPOIListStatusValid
		}
	}
	return out, nil
}

func (node *fakePOINode) GetPOIMerkleProofs(_ context.Context, request GetPOIMerkleProofsRequest) ([]merkletree.MerkleProof, error) {
	proofs := make([]merkletree.MerkleProof, len(request.BlindedCommitments))
	for i, blindedCommitment := range request.BlindedCommitments {
		proofs[i] = merkletree.MerkleProof{Leaf: blindedCommitment, Root: "root"}
	}
	return proofs, nil
}

func (node *fakePOINode) ValidatePOIMerkleRoots(context.Context, ValidatePOIMerkleRootsRequest) (bool, error) {
	return true, nil
}

func (node *fakePOINode) SubmitPOI(_ context.Context, request SubmitPOIRequest) error {
	node.submitPOIRequest = request
	return nil
}

func (node *fakePOINode) SubmitLegacyTransactProofs(_ context.Context, request SubmitLegacyTransactProofsRequest) error {
	node.submitLegacyRequest = request
	return nil
}

func testPOIManager(required bool) *Manager {
	return testPOIManagerWithNode(&fakePOINode{required: required, active: true})
}

func testPOIManagerWithNode(node NodeInterface) *Manager {
	return NewManager([]List{
		{Key: managerMockList, Type: ListTypeGather, Name: "mock list", Description: "mock"},
		{Key: managerActiveList, Type: ListTypeActive, Name: "active list 1", Description: "active-1"},
		{Key: managerActiveList2, Type: ListTypeActive, Name: "active list 2", Description: "active-2"},
	}, node)
}

func statusMap(active1 string, active2 string) POIsPerList {
	return POIsPerList{
		managerActiveList:  active1,
		managerActiveList2: active2,
	}
}

func statusMapAll(mock string, active1 string, active2 string) POIsPerList {
	return POIsPerList{
		managerMockList:    mock,
		managerActiveList:  active1,
		managerActiveList2: active2,
	}
}

func intPtr(value int) *int {
	return &value
}
