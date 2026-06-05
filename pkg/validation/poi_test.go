package validation

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

func TestAssertIsValidSpendableTXIDMatchesTypeScript(t *testing.T) {
	fixture := loadPOIValidationFixtures(t)
	if !fixture.ValidResult {
		t.Fatal("typescript fixture expected valid POI validation result")
	}
	utxoTreesIn := mustBigIntSlice(t, fixture.UTXOTreesIn)
	preTransactionPOIs := fixture.toPreTransactionPOIs()

	err := AssertIsValidSpendableTXID(
		fixture.ListKey,
		preTransactionPOIs,
		fixture.RailgunTxids,
		utxoTreesIn,
		func(listKey string, roots []string) (bool, error) {
			if listKey != fixture.ListKey {
				t.Fatalf("expected list key %s, got %s", fixture.ListKey, listKey)
			}
			if len(roots) == 0 {
				t.Fatal("expected POI roots")
			}
			return true, nil
		},
		func(data TransactProofData) (bool, error) {
			if data.TxidMerkleRoot == "" {
				t.Fatal("expected txid merkle root")
			}
			return true, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	assertPOIValidationError(t, fixture.Errors.MissingList, PreTransactionPOIsPerTxidLeafPerList{}, fixture, utxoTreesIn, true, true)
	assertPOIValidationError(t, fixture.Errors.MissingTxid, PreTransactionPOIsPerTxidLeafPerList{fixture.ListKey: {}}, fixture, utxoTreesIn, true, true)

	invalidRoot := clonePreTransactionPOIs(preTransactionPOIs)
	for txidLeafHash, data := range invalidRoot[fixture.ListKey] {
		data.TxidMerkleRoot = "0000000000000000000000000000000000000000000000000000000000000000"
		invalidRoot[fixture.ListKey][txidLeafHash] = data
		break
	}
	assertPOIValidationError(t, fixture.Errors.InvalidTxidMerkleProof, invalidRoot, fixture, utxoTreesIn, true, true)
	assertPOIValidationError(t, fixture.Errors.InvalidPOIMerkleRoots, preTransactionPOIs, fixture, utxoTreesIn, false, true)
	assertPOIValidationError(t, fixture.Errors.InvalidProof, preTransactionPOIs, fixture, utxoTreesIn, true, false)
}

type poiValidationFixtureSet struct {
	ListKey            string                                        `json:"listKey"`
	RailgunTxids       []string                                      `json:"railgunTxids"`
	UTXOTreesIn        []string                                      `json:"utxoTreesIn"`
	PreTransactionPOIs map[string]map[string]nativeTransactProofData `json:"preTransactionPOIs"`
	ValidResult        bool                                          `json:"validResult"`
	Errors             poiValidationErrors                           `json:"errors"`
}

type nativeTransactProofData struct {
	SnarkProof               railproof.Proof `json:"snarkProof"`
	TxidMerkleRoot           string          `json:"txidMerkleroot"`
	POIMerkleRoots           []string        `json:"poiMerkleroots"`
	BlindedCommitmentsOut    []string        `json:"blindedCommitmentsOut"`
	RailgunTxidIfHasUnshield string          `json:"railgunTxidIfHasUnshield"`
}

type poiValidationErrors struct {
	MissingList            string `json:"missingList"`
	MissingTxid            string `json:"missingTxid"`
	InvalidTxidMerkleProof string `json:"invalidTxidMerkleProof"`
	InvalidPOIMerkleRoots  string `json:"invalidPOIMerkleRoots"`
	InvalidProof           string `json:"invalidProof"`
}

func (fixture poiValidationFixtureSet) toPreTransactionPOIs() PreTransactionPOIsPerTxidLeafPerList {
	out := make(PreTransactionPOIsPerTxidLeafPerList, len(fixture.PreTransactionPOIs))
	for listKey, proofsByTxidLeaf := range fixture.PreTransactionPOIs {
		out[listKey] = make(map[string]TransactProofData, len(proofsByTxidLeaf))
		for txidLeafHash, proofData := range proofsByTxidLeaf {
			out[listKey][txidLeafHash] = TransactProofData{
				SnarkProof:               proofData.SnarkProof,
				TxidMerkleRoot:           proofData.TxidMerkleRoot,
				POIMerkleRoots:           append([]string(nil), proofData.POIMerkleRoots...),
				BlindedCommitmentsOut:    append([]string(nil), proofData.BlindedCommitmentsOut...),
				RailgunTxidIfHasUnshield: proofData.RailgunTxidIfHasUnshield,
			}
		}
	}
	return out
}

func assertPOIValidationError(
	t *testing.T,
	expected string,
	preTransactionPOIs PreTransactionPOIsPerTxidLeafPerList,
	fixture poiValidationFixtureSet,
	utxoTreesIn []*big.Int,
	validRoots bool,
	validProof bool,
) {
	t.Helper()
	err := AssertIsValidSpendableTXID(
		fixture.ListKey,
		preTransactionPOIs,
		fixture.RailgunTxids,
		utxoTreesIn,
		func(string, []string) (bool, error) {
			return validRoots, nil
		},
		func(TransactProofData) (bool, error) {
			return validProof, nil
		},
	)
	if err == nil {
		t.Fatalf("expected error %q", expected)
	}
	if err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}

func clonePreTransactionPOIs(values PreTransactionPOIsPerTxidLeafPerList) PreTransactionPOIsPerTxidLeafPerList {
	out := make(PreTransactionPOIsPerTxidLeafPerList, len(values))
	for listKey, proofsByTxidLeaf := range values {
		out[listKey] = make(map[string]TransactProofData, len(proofsByTxidLeaf))
		for txidLeafHash, proofData := range proofsByTxidLeaf {
			out[listKey][txidLeafHash] = TransactProofData{
				SnarkProof:               proofData.SnarkProof,
				TxidMerkleRoot:           proofData.TxidMerkleRoot,
				POIMerkleRoots:           append([]string(nil), proofData.POIMerkleRoots...),
				BlindedCommitmentsOut:    append([]string(nil), proofData.BlindedCommitmentsOut...),
				RailgunTxidIfHasUnshield: proofData.RailgunTxidIfHasUnshield,
			}
		}
	}
	return out
}

func mustBigIntSlice(t *testing.T, values []string) []*big.Int {
	t.Helper()
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = mustBigInt(t, value)
	}
	return out
}

func loadPOIValidationFixtures(t *testing.T) poiValidationFixtureSet {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.POIValidationFixtures
}
