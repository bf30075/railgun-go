package sdk

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	railproof "github.com/bf30075/railgun-go/pkg/proof"
	railtransaction "github.com/bf30075/railgun-go/pkg/transaction"
)

func TestRuntimeProverForUnshieldUsesRuntimeProofBackend(t *testing.T) {
	backend := &sdkUnshieldProofBackend{}
	runtime := &Runtime{proofBackend: backend}
	manifestPath := writeSDKRailgunArtifactManifest(t, 1, 1)
	unproved := []railtransaction.UnprovedTransactionV2{sdkUnprovedTransactionForProof()}

	prover, resolvedManifest, err := runtime.proverForUnshield(context.Background(), ProofConfig{
		LocalArtifactManifest: manifestPath,
	}, "", unproved, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prover == nil {
		t.Fatal("expected prover")
	}
	if resolvedManifest != manifestPath {
		t.Fatalf("expected manifest %s, got %s", manifestPath, resolvedManifest)
	}

	if _, _, err := prover.ProveRailgun(context.Background(), unproved[0].ProofInputs(), nil); err != nil {
		t.Fatal(err)
	}
	if backend.railgunProofs != 1 {
		t.Fatalf("expected injected backend to prove once, got %d", backend.railgunProofs)
	}
}

type sdkUnshieldProofBackend struct {
	railgunProofs int
}

func (backend *sdkUnshieldProofBackend) ProveRailgun(_ context.Context, _ railproof.CircuitID, inputs railproof.FormattedCircuitInputsRailgun, _ railproof.Artifact, _ railproof.ProgressCallback) (railproof.ProofResult, error) {
	backend.railgunProofs++
	signals := make([]*big.Int, 0, 2+len(inputs.Nullifiers)+len(inputs.CommitmentsOut))
	signals = append(signals, inputs.MerkleRoot, inputs.BoundParamsHash)
	signals = append(signals, inputs.Nullifiers...)
	signals = append(signals, inputs.CommitmentsOut...)
	return railproof.ProofResult{
		Proof:         railtransaction.ZeroProof(),
		PublicSignals: signals,
	}, nil
}

func (*sdkUnshieldProofBackend) VerifyRailgun(context.Context, railproof.PublicInputsRailgun, railproof.Proof, railproof.Artifact) (bool, error) {
	return true, nil
}

func (*sdkUnshieldProofBackend) ProvePOI(context.Context, railproof.CircuitID, railproof.FormattedCircuitInputsPOI, railproof.Artifact, railproof.ProgressCallback) (railproof.ProofResult, error) {
	return railproof.ProofResult{}, nil
}

func (*sdkUnshieldProofBackend) VerifyPOI(context.Context, railproof.PublicInputsPOI, railproof.Proof, railproof.Artifact) (bool, error) {
	return true, nil
}

func sdkUnprovedTransactionForProof() railtransaction.UnprovedTransactionV2 {
	return railtransaction.UnprovedTransactionV2{
		Request: railtransaction.TransactionRequestV2{
			PublicInputs: railproof.PublicInputsRailgun{
				MerkleRoot:      big.NewInt(5),
				BoundParamsHash: big.NewInt(6),
				Nullifiers:      []*big.Int{big.NewInt(7)},
				CommitmentsOut:  []*big.Int{big.NewInt(8)},
			},
			PrivateInputs: railproof.PrivateInputsRailgun{
				TokenAddress:  big.NewInt(1),
				PublicKey:     [2]*big.Int{big.NewInt(2), big.NewInt(3)},
				NullifyingKey: big.NewInt(4),
			},
		},
		Signature: [3]*big.Int{big.NewInt(9), big.NewInt(10), big.NewInt(11)},
	}
}

func writeSDKRailgunArtifactManifest(t *testing.T, nullifiers int, commitments int) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"railgun.wasm", "railgun.zkey"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := `{
		"railgun": {
			"` + railproof.RailgunArtifactKey(nullifiers, commitments) + `": {
				"wasm": "railgun.wasm",
				"zkey": "railgun.zkey"
			}
		}
	}`
	path := filepath.Join(dir, "railgun-artifacts.json")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
