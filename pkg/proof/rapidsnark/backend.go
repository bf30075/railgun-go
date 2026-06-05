//go:build rapidsnark

package rapidsnark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bf30075/railgun-go/pkg/proof"
	"github.com/bf30075/railgun-go/pkg/proof/groth16"
)

var ErrWitnessGenerationNotImplemented = errors.New("rapidsnark witness generation from formatted inputs requires the witnesscalc build tag")
var ErrVerificationKeyRequired = errors.New("verification key artifact is required for strict proof verification")

type WTNSProver interface {
	ProveWTNS(ctx context.Context, zkey []byte, wtns []byte) ([]byte, []byte, error)
}

type Backend struct {
	ProverBinary string
	WorkDir      string
	StrictVerify bool
	WTNSProver   WTNSProver
}

func New(proverBinary string) *Backend {
	return &Backend{ProverBinary: proverBinary, StrictVerify: true}
}

type CLIWTNSProver struct {
	ProverBinary string
	WorkDir      string
}

func NewCLIWTNSProver(proverBinary string) *CLIWTNSProver {
	return &CLIWTNSProver{ProverBinary: proverBinary}
}

func (b *Backend) ProveRailgun(ctx context.Context, _ proof.CircuitID, inputs proof.FormattedCircuitInputsRailgun, artifacts proof.Artifact, progress proof.ProgressCallback) (proof.ProofResult, error) {
	if progress != nil {
		progress(5)
	}
	wtns, err := calculateWTNSRailgun(inputs, artifacts)
	if err != nil {
		return proof.ProofResult{}, err
	}
	if progress != nil {
		progress(60)
	}
	result, err := b.ProveWTNSResult(ctx, artifacts.ZKey, wtns)
	if err != nil {
		return proof.ProofResult{}, err
	}
	if progress != nil {
		progress(100)
	}
	return result, nil
}

func (b *Backend) VerifyRailgun(_ context.Context, publicInputs proof.PublicInputsRailgun, snarkProof proof.Proof, artifacts proof.Artifact) (bool, error) {
	return verifyWithVKey(proof.BuildPublicSignalsRailgun(publicInputs), snarkProof, artifacts, b.StrictVerify)
}

func (b *Backend) ProvePOI(ctx context.Context, _ proof.CircuitID, inputs proof.FormattedCircuitInputsPOI, artifacts proof.Artifact, progress proof.ProgressCallback) (proof.ProofResult, error) {
	if progress != nil {
		progress(5)
	}
	wtns, err := calculateWTNSPOI(inputs, artifacts)
	if err != nil {
		return proof.ProofResult{}, err
	}
	if progress != nil {
		progress(60)
	}
	result, err := b.ProveWTNSResult(ctx, artifacts.ZKey, wtns)
	if err != nil {
		return proof.ProofResult{}, err
	}
	if progress != nil {
		progress(100)
	}
	return result, nil
}

func (b *Backend) VerifyPOI(_ context.Context, publicInputs proof.PublicInputsPOI, snarkProof proof.Proof, artifacts proof.Artifact) (bool, error) {
	return verifyWithVKey(proof.BuildPublicSignalsPOI(publicInputs), snarkProof, artifacts, b.StrictVerify)
}

func (b *Backend) ProveWTNS(ctx context.Context, zkey []byte, wtns []byte) ([]byte, []byte, error) {
	return b.wtnsProver().ProveWTNS(ctx, zkey, wtns)
}

func (b *Backend) wtnsProver() WTNSProver {
	if b.WTNSProver != nil {
		return b.WTNSProver
	}
	return &CLIWTNSProver{
		ProverBinary: b.ProverBinary,
		WorkDir:      b.WorkDir,
	}
}

func (p *CLIWTNSProver) ProveWTNS(ctx context.Context, zkey []byte, wtns []byte) ([]byte, []byte, error) {
	proverBinary := p.ProverBinary
	if proverBinary == "" {
		var err error
		proverBinary, err = exec.LookPath("prover")
		if err != nil {
			return nil, nil, err
		}
	}

	workDir := p.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.MkdirTemp("", "railgun-go-rapidsnark-*")
		if err != nil {
			return nil, nil, err
		}
		defer os.RemoveAll(workDir)
	}

	zkeyPath := filepath.Join(workDir, "circuit.zkey")
	wtnsPath := filepath.Join(workDir, "witness.wtns")
	proofPath := filepath.Join(workDir, "proof.json")
	publicPath := filepath.Join(workDir, "public.json")

	if err := os.WriteFile(zkeyPath, zkey, 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(wtnsPath, wtns, 0o600); err != nil {
		return nil, nil, err
	}

	cmd := exec.CommandContext(ctx, proverBinary, zkeyPath, wtnsPath, proofPath, publicPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, nil, errors.Join(err, errors.New(string(out)))
	}

	proofJSON, err := os.ReadFile(proofPath)
	if err != nil {
		return nil, nil, err
	}
	publicJSON, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, nil, err
	}
	return proofJSON, publicJSON, nil
}

func (b *Backend) ProveWTNSResult(ctx context.Context, zkey []byte, wtns []byte) (proof.ProofResult, error) {
	proofJSON, publicJSON, err := b.ProveWTNS(ctx, zkey, wtns)
	if err != nil {
		return proof.ProofResult{}, err
	}
	return ParseProofResult(proofJSON, publicJSON)
}

func ParseProofResult(proofJSON []byte, publicJSON []byte) (proof.ProofResult, error) {
	var parsedProof proof.Proof
	if err := json.Unmarshal(proofJSON, &parsedProof); err != nil {
		return proof.ProofResult{}, fmt.Errorf("proof JSON: %w", err)
	}
	publicSignals, err := parsePublicSignals(publicJSON)
	if err != nil {
		return proof.ProofResult{}, fmt.Errorf("public JSON: %w", err)
	}
	return proof.ProofResult{
		Proof:         parsedProof,
		PublicSignals: publicSignals,
	}, nil
}

func parsePublicSignals(publicJSON []byte) ([]*big.Int, error) {
	var raw []string
	if err := json.Unmarshal(publicJSON, &raw); err != nil {
		return nil, err
	}
	out := make([]*big.Int, len(raw))
	for i, value := range raw {
		n, err := proof.ParseNumberishBigInt(value)
		if err != nil {
			return nil, fmt.Errorf("public signal %d: %w", i, err)
		}
		out[i] = n
	}
	return out, nil
}

func verifyWithVKey(publicSignals []*big.Int, snarkProof proof.Proof, artifacts proof.Artifact, strict bool) (bool, error) {
	if artifacts.VKey == nil {
		if strict {
			return false, ErrVerificationKeyRequired
		}
		return true, nil
	}
	vkey, err := verificationKeyFromArtifact(artifacts.VKey)
	if err != nil {
		return false, err
	}
	return groth16.Verify(vkey, publicSignals, snarkProof)
}

func verificationKeyFromArtifact(value any) (groth16.VerificationKey, error) {
	switch typed := value.(type) {
	case groth16.VerificationKey:
		return typed, nil
	case *groth16.VerificationKey:
		if typed == nil {
			return groth16.VerificationKey{}, errors.New("nil verification key")
		}
		return *typed, nil
	case json.RawMessage:
		return groth16.ParseVerificationKey(typed)
	case []byte:
		return groth16.ParseVerificationKey(typed)
	case string:
		return groth16.ParseVerificationKey([]byte(typed))
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return groth16.VerificationKey{}, fmt.Errorf("verification key: %w", err)
		}
		return groth16.ParseVerificationKey(data)
	}
}
