package poi

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
)

func TestPreparePreTransactionPOIInputsMatchesTypeScriptFixture(t *testing.T) {
	fixture := loadPreTransactionPOIFixture(t)
	if !fixture.Prepared.TxidMerkleProofVerified {
		t.Fatal("typescript fixture txid merkle proof did not verify")
	}
	for i, verified := range fixture.Prepared.POIMerkleProofsVerified {
		if !verified {
			t.Fatalf("typescript fixture poi merkle proof %d did not verify", i)
		}
	}

	prepared, err := PreparePreTransactionPOIInputs(fixture.Input.toInputs(t))
	if err != nil {
		t.Fatal(err)
	}
	expectedInputs, err := railproof.ParsePOIEngineProofInputsJSON(fixture.Prepared.ProofInputs)
	if err != nil {
		t.Fatal(err)
	}

	if prepared.TxidLeafHash != fixture.Prepared.TxidLeafHash {
		t.Fatalf("expected txid leaf hash %s, got %s", fixture.Prepared.TxidLeafHash, prepared.TxidLeafHash)
	}
	if prepared.TxidMerkleRoot != fixture.Prepared.TxidMerkleRoot {
		t.Fatalf("expected txid merkle root %s, got %s", fixture.Prepared.TxidMerkleRoot, prepared.TxidMerkleRoot)
	}
	if !reflect.DeepEqual(prepared.TxidMerkleProof, fixture.Prepared.TxidMerkleProof) {
		t.Fatalf("unexpected txid merkle proof\nwant: %+v\n got: %+v", fixture.Prepared.TxidMerkleProof, prepared.TxidMerkleProof)
	}
	assertStringSlices(t, prepared.POIMerkleRoots, fixture.Prepared.POIMerkleRoots, "poi merkle roots")
	assertStringSlices(t, prepared.BlindedCommitmentsIn, fixture.Prepared.BlindedCommitmentsIn, "blinded commitments in")
	assertStringSlices(t, prepared.BlindedCommitmentsOut, fixture.Prepared.BlindedCommitmentsOut, "blinded commitments out")
	if prepared.RailgunTxidIfHasUnshield != fixture.Prepared.RailgunTxidIfHasUnshield {
		t.Fatalf("expected railgunTxidIfHasUnshield %s, got %s", fixture.Prepared.RailgunTxidIfHasUnshield, prepared.RailgunTxidIfHasUnshield)
	}
	assertPOIEngineInputsEqual(t, prepared.ProofInputs, expectedInputs)

	formatted, err := railproof.FormatPOIInputs(prepared.ProofInputs, len(fixture.Prepared.Formatted.Nullifiers), len(fixture.Prepared.Formatted.CommitmentsOut))
	if err != nil {
		t.Fatal(err)
	}
	if got := formatted.NativeInputs(); !reflect.DeepEqual(got, fixture.Prepared.Formatted) {
		t.Fatalf("formatted inputs mismatch\nwant: %+v\n got: %+v", fixture.Prepared.Formatted, got)
	}
}

func TestGeneratePreTransactionPOIUsesProver(t *testing.T) {
	fixture := loadPreTransactionPOIFixture(t)
	inputs := fixture.Input.toInputs(t)
	prepared, err := PreparePreTransactionPOIInputs(inputs)
	if err != nil {
		t.Fatal(err)
	}
	publicInputs, err := railproof.GetPublicInputsPOI(
		prepared.TxidMerkleRoot,
		prepared.BlindedCommitmentsOut,
		prepared.POIMerkleRoots,
		prepared.RailgunTxidIfHasUnshield,
		len(fixture.Prepared.Formatted.Nullifiers),
		len(fixture.Prepared.Formatted.CommitmentsOut),
	)
	if err != nil {
		t.Fatal(err)
	}
	prover := railproof.NewProver(testArtifactGetter{}, testProofBackend{
		poiSignals: railproof.BuildPublicSignalsPOI(publicInputs),
	})

	generated, err := GeneratePreTransactionPOI(context.Background(), prover, inputs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if generated.PreparedPreTransactionPOI.TxidLeafHash != fixture.Prepared.TxidLeafHash {
		t.Fatalf("expected generated txid leaf hash %s, got %s", fixture.Prepared.TxidLeafHash, generated.PreparedPreTransactionPOI.TxidLeafHash)
	}
	if !reflect.DeepEqual(generated.PreTransactionPOI.SnarkProof, zeroProof()) {
		t.Fatalf("unexpected snark proof: %+v", generated.PreTransactionPOI.SnarkProof)
	}
	if generated.PreTransactionPOI.TxidMerkleRoot != fixture.Prepared.TxidMerkleRoot {
		t.Fatalf("expected txid merkle root %s, got %s", fixture.Prepared.TxidMerkleRoot, generated.PreTransactionPOI.TxidMerkleRoot)
	}
	assertStringSlices(t, generated.PreTransactionPOI.POIMerkleRoots, fixture.Prepared.POIMerkleRoots, "generated poi merkle roots")
	assertStringSlices(t, generated.PreTransactionPOI.BlindedCommitmentsOut, fixture.Prepared.BlindedCommitmentsOut, "generated blinded commitments out")
	if generated.PreTransactionPOI.RailgunTxidIfHasUnshield != fixture.Prepared.RailgunTxidIfHasUnshield {
		t.Fatalf("expected generated railgunTxidIfHasUnshield %s, got %s", fixture.Prepared.RailgunTxidIfHasUnshield, generated.PreTransactionPOI.RailgunTxidIfHasUnshield)
	}
}

func TestPreparePreTransactionPOIInputsCanUseLocalTXIDMerkleProof(t *testing.T) {
	ctx := context.Background()
	fixture := loadPreTransactionPOIFixture(t)
	inputs := fixture.Input.toInputs(t)
	_, txidLeafHash, err := preTransactionTXIDLeafHash(inputs, GlobalTreePositionPreTransactionPOIProof())
	if err != nil {
		t.Fatal(err)
	}
	otherHash, err := railcrypto.BigIntToHex(big.NewInt(1), 32, true)
	if err != nil {
		t.Fatal(err)
	}
	if sameHex(otherHash, txidLeafHash) {
		otherHash, err = railcrypto.BigIntToHex(big.NewInt(2), 32, true)
		if err != nil {
			t.Fatal(err)
		}
	}
	txidTree := railtxid.NewMemoryMerkleTreeStore()
	if err := txidTree.UpsertLeaf(ctx, railtxid.MerkleLeaf{
		Tree:  0,
		Index: 0,
		Hash:  otherHash,
	}); err != nil {
		t.Fatal(err)
	}
	if err := txidTree.UpsertLeaf(ctx, railtxid.MerkleLeaf{
		Tree:  0,
		Index: 1,
		Hash:  txidLeafHash,
	}); err != nil {
		t.Fatal(err)
	}

	prepared, err := PreparePreTransactionPOIInputsWithTXIDMerkleTree(ctx, txidTree, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if !sameHex(prepared.TxidMerkleProof.Leaf, txidLeafHash) {
		t.Fatalf("expected local txid proof leaf %s, got %s", txidLeafHash, prepared.TxidMerkleProof.Leaf)
	}
	if sameHex(prepared.TxidMerkleRoot, fixture.Prepared.TxidMerkleRoot) {
		t.Fatalf("expected local txid merkle root to differ from dummy root %s", fixture.Prepared.TxidMerkleRoot)
	}
	ok, err := merkletree.VerifyProof(prepared.TxidMerkleProof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected local txid merkle proof to verify")
	}
	if prepared.ProofInputs.AnyRailgunTxidMerklerootAfterTransaction != prepared.TxidMerkleRoot {
		t.Fatalf("expected proof inputs to use local txid merkle root")
	}
}

func TestSubmitPreTransactionPOIBuildsNodeRequest(t *testing.T) {
	ctx := context.Background()
	node := &fakePOINode{required: true, active: true}
	manager := testPOIManagerWithNode(node)
	chain := railchain.Chain{Type: 0, ID: 1}
	poi := PreTransactionPOI{
		SnarkProof:               zeroProof(),
		TxidMerkleRoot:           "0xroot",
		POIMerkleRoots:           []string{"0xpoi"},
		BlindedCommitmentsOut:    []string{"0xout"},
		RailgunTxidIfHasUnshield: "0xrailgun",
	}

	if err := SubmitPreTransactionPOI(ctx, manager, "V3_PoseidonMerkle", chain, managerActiveList, 7, poi); err != nil {
		t.Fatal(err)
	}
	request := node.submitPOIRequest
	if request.TXIDVersion != "V3_PoseidonMerkle" || request.Chain != chain || request.ListKey != managerActiveList {
		t.Fatalf("unexpected submit request routing fields %+v", request)
	}
	if request.TxidMerkleRoot != poi.TxidMerkleRoot || request.TxidMerkleRootIndex != 7 {
		t.Fatalf("unexpected txid merkle fields %+v", request)
	}
	assertStringSlices(t, request.POIMerkleRoots, poi.POIMerkleRoots, "submit poi roots")
	assertStringSlices(t, request.BlindedCommitmentsOut, poi.BlindedCommitmentsOut, "submit blinded outputs")
	if request.RailgunTxidIfHasUnshield != poi.RailgunTxidIfHasUnshield {
		t.Fatalf("expected unshield txid %s, got %s", poi.RailgunTxidIfHasUnshield, request.RailgunTxidIfHasUnshield)
	}
}

func TestGenerateAndSubmitPreTransactionPOIFetchesProofsAndSubmits(t *testing.T) {
	ctx := context.Background()
	fixture := loadPreTransactionPOIFixture(t)
	inputs := fixture.Input.toInputs(t)
	inputs.POIMerkleProofs = nil
	publicInputs, err := railproof.GetPublicInputsPOI(
		fixture.Prepared.TxidMerkleRoot,
		fixture.Prepared.BlindedCommitmentsOut,
		fixture.Prepared.POIMerkleRoots,
		fixture.Prepared.RailgunTxidIfHasUnshield,
		len(fixture.Prepared.Formatted.Nullifiers),
		len(fixture.Prepared.Formatted.CommitmentsOut),
	)
	if err != nil {
		t.Fatal(err)
	}
	node := &preTransactionPOINode{
		fakePOINode: fakePOINode{required: true, active: true},
		proofs:      fixture.Input.POIMerkleProofs,
	}
	manager := testPOIManagerWithNode(node)
	prover := railproof.NewProver(testArtifactGetter{}, testProofBackend{
		poiSignals: railproof.BuildPublicSignalsPOI(publicInputs),
	})
	chain := railchain.Chain{Type: 0, ID: 1}

	submitted, err := GenerateAndSubmitPreTransactionPOI(ctx, manager, prover, GenerateAndSubmitPreTransactionPOIRequest{
		TXIDVersion:         "V3_PoseidonMerkle",
		Chain:               chain,
		ListKey:             managerActiveList,
		TXIDMerkleRootIndex: 11,
		Inputs:              inputs,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if node.getProofsRequest.TXIDVersion != "V3_PoseidonMerkle" || node.getProofsRequest.Chain != chain || node.getProofsRequest.ListKey != managerActiveList {
		t.Fatalf("unexpected proof request %+v", node.getProofsRequest)
	}
	assertStringSlices(t, node.getProofsRequest.BlindedCommitments, fixture.Prepared.BlindedCommitmentsIn, "proof request blinded commitments")
	if submitted.GeneratedPreTransactionPOI.PreparedPreTransactionPOI.TxidLeafHash != fixture.Prepared.TxidLeafHash {
		t.Fatalf("expected txid leaf %s, got %s", fixture.Prepared.TxidLeafHash, submitted.GeneratedPreTransactionPOI.PreparedPreTransactionPOI.TxidLeafHash)
	}
	request := node.submitPOIRequest
	if request.TxidMerkleRootIndex != 11 || request.TxidMerkleRoot != fixture.Prepared.TxidMerkleRoot {
		t.Fatalf("unexpected submit request %+v", request)
	}
	assertStringSlices(t, request.POIMerkleRoots, fixture.Prepared.POIMerkleRoots, "submit poi roots")
	assertStringSlices(t, request.BlindedCommitmentsOut, fixture.Prepared.BlindedCommitmentsOut, "submit blinded outputs")
	if request.RailgunTxidIfHasUnshield != fixture.Prepared.RailgunTxidIfHasUnshield {
		t.Fatalf("expected unshield txid %s, got %s", fixture.Prepared.RailgunTxidIfHasUnshield, request.RailgunTxidIfHasUnshield)
	}
}

func TestGenerateAndSubmitPreTransactionPOIsRunsEveryList(t *testing.T) {
	ctx := context.Background()
	fixture := loadPreTransactionPOIFixture(t)
	inputs := fixture.Input.toInputs(t)
	inputs.POIMerkleProofs = nil
	publicInputs, err := railproof.GetPublicInputsPOI(
		fixture.Prepared.TxidMerkleRoot,
		fixture.Prepared.BlindedCommitmentsOut,
		fixture.Prepared.POIMerkleRoots,
		fixture.Prepared.RailgunTxidIfHasUnshield,
		len(fixture.Prepared.Formatted.Nullifiers),
		len(fixture.Prepared.Formatted.CommitmentsOut),
	)
	if err != nil {
		t.Fatal(err)
	}
	node := &preTransactionPOINode{
		fakePOINode: fakePOINode{required: true, active: true},
		proofs:      fixture.Input.POIMerkleProofs,
	}
	manager := testPOIManagerWithNode(node)
	prover := railproof.NewProver(testArtifactGetter{}, testProofBackend{
		poiSignals: railproof.BuildPublicSignalsPOI(publicInputs),
	})

	submitted, err := GenerateAndSubmitPreTransactionPOIs(ctx, manager, prover, GenerateAndSubmitPreTransactionPOIsRequest{
		TXIDVersion:         "V3_PoseidonMerkle",
		Chain:               railchain.Chain{Type: 0, ID: 1},
		ListKeys:            []string{managerActiveList, managerActiveList2},
		TXIDMerkleRootIndex: 12,
		Inputs:              inputs,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(submitted) != 2 || len(node.submitRequests) != 2 || len(node.getProofsRequests) != 2 {
		t.Fatalf("expected two generated/submitted POIs, got submitted=%d submitRequests=%d proofRequests=%d", len(submitted), len(node.submitRequests), len(node.getProofsRequests))
	}
	if node.submitRequests[0].ListKey != managerActiveList || node.submitRequests[1].ListKey != managerActiveList2 {
		t.Fatalf("unexpected submitted list keys %+v", node.submitRequests)
	}
	for _, result := range submitted {
		if result.SubmitRequest.TxidMerkleRoot != fixture.Prepared.TxidMerkleRoot {
			t.Fatalf("unexpected txid root %s", result.SubmitRequest.TxidMerkleRoot)
		}
	}
}

type exportedFixtures struct {
	PreTransactionPOIFixtures []preTransactionPOIFixture `json:"preTransactionPOIFixtures"`
}

type preTransactionPOIFixture struct {
	Name     string                           `json:"name"`
	Input    preTransactionPOIInputFixture    `json:"input"`
	Prepared preTransactionPOIPreparedFixture `json:"prepared"`
}

type preTransactionPOIInputFixture struct {
	PublicInputs      publicInputsRailgunFixture `json:"publicInputs"`
	PrivateInputs     privateInputsPOIFixture    `json:"privateInputs"`
	SpendingPublicKey [2]string                  `json:"spendingPublicKey"`
	NullifyingKey     string                     `json:"nullifyingKey"`
	UTXOs             []utxoPOIFixture           `json:"utxos"`
	POIMerkleProofs   []merkletree.MerkleProof   `json:"poiMerkleProofs"`
	TreeNumber        string                     `json:"treeNumber"`
	HasUnshield       bool                       `json:"hasUnshield"`
}

type publicInputsRailgunFixture struct {
	MerkleRoot      string   `json:"merkleRoot"`
	BoundParamsHash string   `json:"boundParamsHash"`
	Nullifiers      []string `json:"nullifiers"`
	CommitmentsOut  []string `json:"commitmentsOut"`
}

type privateInputsPOIFixture struct {
	NPKOut   []string `json:"npkOut"`
	ValueOut []string `json:"valueOut"`
}

type utxoPOIFixture struct {
	Tree              string `json:"tree"`
	Position          string `json:"position"`
	TokenHash         string `json:"tokenHash"`
	Random            string `json:"random"`
	Value             string `json:"value"`
	BlindedCommitment string `json:"blindedCommitment"`
}

type preTransactionPOIPreparedFixture struct {
	TxidLeafHash             string                                    `json:"txidLeafHash"`
	TxidMerkleRoot           string                                    `json:"txidMerkleRoot"`
	POIMerkleRoots           []string                                  `json:"poiMerkleroots"`
	BlindedCommitmentsIn     []string                                  `json:"blindedCommitmentsIn"`
	BlindedCommitmentsOut    []string                                  `json:"blindedCommitmentsOut"`
	RailgunTxidIfHasUnshield string                                    `json:"railgunTxidIfHasUnshield"`
	ProofInputs              json.RawMessage                           `json:"proofInputs"`
	Formatted                railproof.NativeFormattedCircuitInputsPOI `json:"formatted"`
	TxidMerkleProof          merkletree.MerkleProof                    `json:"txidMerkleProof"`
	TxidMerkleProofVerified  bool                                      `json:"txidMerkleProofVerified"`
	POIMerkleProofsVerified  []bool                                    `json:"poiMerkleProofsVerified"`
}

func (fixture preTransactionPOIInputFixture) toInputs(t *testing.T) PreTransactionPOIInputs {
	t.Helper()
	treeNumber, err := strconv.ParseUint(fixture.TreeNumber, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	utxos := make([]PreTransactionUTXO, len(fixture.UTXOs))
	for i, utxo := range fixture.UTXOs {
		tree, err := strconv.ParseUint(utxo.Tree, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		position, err := strconv.ParseUint(utxo.Position, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		utxos[i] = PreTransactionUTXO{
			Tree:              tree,
			Position:          position,
			TokenHash:         utxo.TokenHash,
			Random:            utxo.Random,
			Value:             mustNumberish(t, utxo.Value),
			BlindedCommitment: utxo.BlindedCommitment,
		}
	}
	return PreTransactionPOIInputs{
		PublicInputs: railproof.PublicInputsRailgun{
			MerkleRoot:      mustNumberish(t, fixture.PublicInputs.MerkleRoot),
			BoundParamsHash: mustNumberish(t, fixture.PublicInputs.BoundParamsHash),
			Nullifiers:      mustNumberishSlice(t, fixture.PublicInputs.Nullifiers),
			CommitmentsOut:  mustNumberishSlice(t, fixture.PublicInputs.CommitmentsOut),
		},
		PrivateInputs: railproof.PrivateInputsRailgun{
			NPKOut:   mustNumberishSlice(t, fixture.PrivateInputs.NPKOut),
			ValueOut: mustNumberishSlice(t, fixture.PrivateInputs.ValueOut),
		},
		SpendingPublicKey: [2]*big.Int{
			mustNumberish(t, fixture.SpendingPublicKey[0]),
			mustNumberish(t, fixture.SpendingPublicKey[1]),
		},
		NullifyingKey:   mustNumberish(t, fixture.NullifyingKey),
		UTXOs:           utxos,
		POIMerkleProofs: fixture.POIMerkleProofs,
		TreeNumber:      treeNumber,
		HasUnshield:     fixture.HasUnshield,
	}
}

func loadPreTransactionPOIFixture(t *testing.T) preTransactionPOIFixture {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures.PreTransactionPOIFixtures {
		if fixture.Name == "test-vector-has-unshield" {
			return fixture
		}
	}
	t.Fatal("missing pre-transaction POI fixture")
	return preTransactionPOIFixture{}
}

func mustNumberish(t *testing.T, value string) *big.Int {
	t.Helper()
	n, err := railproof.ParseNumberishBigInt(value)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mustNumberishSlice(t *testing.T, values []string) []*big.Int {
	t.Helper()
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = mustNumberish(t, value)
	}
	return out
}

func assertPOIEngineInputsEqual(t *testing.T, got railproof.POIEngineProofInputs, want railproof.POIEngineProofInputs) {
	t.Helper()
	if got.AnyRailgunTxidMerklerootAfterTransaction != want.AnyRailgunTxidMerklerootAfterTransaction ||
		got.BoundParamsHash != want.BoundParamsHash ||
		got.Token != want.Token ||
		got.UTXOTreeIn != want.UTXOTreeIn ||
		got.RailgunTxidIfHasUnshield != want.RailgunTxidIfHasUnshield ||
		got.RailgunTxidMerkleProofIndices != want.RailgunTxidMerkleProofIndices ||
		got.UTXOBatchGlobalStartPositionOut.Cmp(want.UTXOBatchGlobalStartPositionOut) != 0 ||
		got.NullifyingKey.Cmp(want.NullifyingKey) != 0 ||
		got.SpendingPublicKey[0].Cmp(want.SpendingPublicKey[0]) != 0 ||
		got.SpendingPublicKey[1].Cmp(want.SpendingPublicKey[1]) != 0 {
		t.Fatalf("POI engine scalar inputs mismatch\nwant: %+v\n got: %+v", want, got)
	}
	assertStringSlices(t, got.Nullifiers, want.Nullifiers, "nullifiers")
	assertStringSlices(t, got.CommitmentsOut, want.CommitmentsOut, "commitmentsOut")
	assertStringSlices(t, got.RandomsIn, want.RandomsIn, "randomsIn")
	assertStringSlices(t, got.RailgunTxidMerkleProofPathElements, want.RailgunTxidMerkleProofPathElements, "txid path")
	assertStringSlices(t, got.POIMerkleRoots, want.POIMerkleRoots, "poi roots")
	assertStringSlices(t, got.POIInMerkleProofIndices, want.POIInMerkleProofIndices, "poi indices")
	assertBigIntSlices(t, got.ValuesIn, want.ValuesIn, "valuesIn")
	assertBigIntSlices(t, got.NPKsOut, want.NPKsOut, "npksOut")
	assertBigIntSlices(t, got.ValuesOut, want.ValuesOut, "valuesOut")
	if !reflect.DeepEqual(got.UTXOPositionsIn, want.UTXOPositionsIn) {
		t.Fatalf("utxoPositionsIn mismatch\nwant: %+v\n got: %+v", want.UTXOPositionsIn, got.UTXOPositionsIn)
	}
	if !reflect.DeepEqual(got.POIInMerkleProofPathElements, want.POIInMerkleProofPathElements) {
		t.Fatalf("poi path elements mismatch\nwant: %+v\n got: %+v", want.POIInMerkleProofPathElements, got.POIInMerkleProofPathElements)
	}
}

func assertStringSlices(t *testing.T, got []string, want []string, name string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s length mismatch: want %d got %d", name, len(want), len(got))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] mismatch: want %s got %s", name, i, want[i], got[i])
		}
	}
}

func assertBigIntSlices(t *testing.T, got []*big.Int, want []*big.Int, name string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s length mismatch: want %d got %d", name, len(want), len(got))
	}
	for i := range got {
		if got[i].Cmp(want[i]) != 0 {
			t.Fatalf("%s[%d] mismatch: want %s got %s", name, i, want[i], got[i])
		}
	}
}

type testArtifactGetter struct{}

func (testArtifactGetter) AssertArtifactExists(_ int, _ int) error {
	return nil
}

func (testArtifactGetter) GetArtifacts(_ context.Context, _ railproof.PublicInputsRailgun) (railproof.Artifact, error) {
	return railproof.Artifact{}, nil
}

func (testArtifactGetter) GetArtifactsPOI(_ context.Context, _ int, _ int) (railproof.Artifact, error) {
	return railproof.Artifact{}, nil
}

type testProofBackend struct {
	poiSignals []*big.Int
}

func (backend testProofBackend) ProveRailgun(_ context.Context, _ railproof.CircuitID, _ railproof.FormattedCircuitInputsRailgun, _ railproof.Artifact, _ railproof.ProgressCallback) (railproof.ProofResult, error) {
	return railproof.ProofResult{Proof: zeroProof()}, nil
}

func (backend testProofBackend) VerifyRailgun(_ context.Context, _ railproof.PublicInputsRailgun, _ railproof.Proof, _ railproof.Artifact) (bool, error) {
	return true, nil
}

func (backend testProofBackend) ProvePOI(_ context.Context, _ railproof.CircuitID, _ railproof.FormattedCircuitInputsPOI, _ railproof.Artifact, _ railproof.ProgressCallback) (railproof.ProofResult, error) {
	return railproof.ProofResult{Proof: zeroProof(), PublicSignals: backend.poiSignals}, nil
}

func (backend testProofBackend) VerifyPOI(_ context.Context, _ railproof.PublicInputsPOI, _ railproof.Proof, _ railproof.Artifact) (bool, error) {
	return true, nil
}

func zeroProof() railproof.Proof {
	return railproof.Proof{
		PiA: [2]string{"00", "00"},
		PiB: [2][2]string{{"00", "00"}, {"00", "00"}},
		PiC: [2]string{"00", "00"},
	}
}

type preTransactionPOINode struct {
	fakePOINode
	proofs            []merkletree.MerkleProof
	getProofsRequest  GetPOIMerkleProofsRequest
	getProofsRequests []GetPOIMerkleProofsRequest
	submitRequests    []SubmitPOIRequest
}

func (node *preTransactionPOINode) GetPOIMerkleProofs(_ context.Context, request GetPOIMerkleProofsRequest) ([]merkletree.MerkleProof, error) {
	node.getProofsRequest = request
	node.getProofsRequests = append(node.getProofsRequests, request)
	proofs := make([]merkletree.MerkleProof, len(node.proofs))
	for i, proof := range node.proofs {
		proofs[i] = cloneMerkleProof(proof)
	}
	return proofs, nil
}

func (node *preTransactionPOINode) SubmitPOI(_ context.Context, request SubmitPOIRequest) error {
	node.submitPOIRequest = request
	node.submitRequests = append(node.submitRequests, request)
	return nil
}
