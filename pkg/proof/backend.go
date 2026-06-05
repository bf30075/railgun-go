package proof

import (
	"context"
	"errors"
	"fmt"
)

var ErrBackendNotConfigured = errors.New("proof backend not configured")

type Backend interface {
	ProveRailgun(ctx context.Context, circuit CircuitID, inputs FormattedCircuitInputsRailgun, artifacts Artifact, progress ProgressCallback) (ProofResult, error)
	VerifyRailgun(ctx context.Context, publicInputs PublicInputsRailgun, proof Proof, artifacts Artifact) (bool, error)
	ProvePOI(ctx context.Context, circuit CircuitID, inputs FormattedCircuitInputsPOI, artifacts Artifact, progress ProgressCallback) (ProofResult, error)
	VerifyPOI(ctx context.Context, publicInputs PublicInputsPOI, proof Proof, artifacts Artifact) (bool, error)
}

type Prover struct {
	artifactGetter ArtifactGetter
	backend        Backend
}

func NewProver(artifactGetter ArtifactGetter, backend Backend) *Prover {
	return &Prover{
		artifactGetter: artifactGetter,
		backend:        backend,
	}
}

func (p *Prover) SetBackend(backend Backend) {
	p.backend = backend
}

func (p *Prover) ProveRailgun(
	ctx context.Context,
	unprovedInputs UnprovedTransactionInputs,
	progress ProgressCallback,
) (Proof, PublicInputsRailgun, error) {
	if p.backend == nil {
		return Proof{}, PublicInputsRailgun{}, ErrBackendNotConfigured
	}
	if p.artifactGetter == nil {
		return Proof{}, PublicInputsRailgun{}, errors.New("artifact getter not configured")
	}

	formattedInputs, err := FormatRailgunInputs(unprovedInputs)
	if err != nil {
		return Proof{}, PublicInputsRailgun{}, err
	}
	publicInputs := unprovedInputs.PublicInputs
	artifacts, err := p.artifactGetter.GetArtifacts(ctx, publicInputs)
	if err != nil {
		return Proof{}, PublicInputsRailgun{}, err
	}
	circuit := RailgunCircuitID(len(publicInputs.Nullifiers), len(publicInputs.CommitmentsOut))
	result, err := p.backend.ProveRailgun(ctx, circuit, formattedInputs, artifacts, progress)
	if err != nil {
		return Proof{}, PublicInputsRailgun{}, err
	}
	if err := AssertPublicSignalsMatch(BuildPublicSignalsRailgun(publicInputs), result.PublicSignals); err != nil {
		return Proof{}, PublicInputsRailgun{}, err
	}
	ok, err := p.backend.VerifyRailgun(ctx, publicInputs, result.Proof, artifacts)
	if err != nil {
		return Proof{}, PublicInputsRailgun{}, err
	}
	if !ok {
		return Proof{}, PublicInputsRailgun{}, errors.New("railgun proof verification failed")
	}
	return result.Proof, publicInputs, nil
}

func (p *Prover) ProvePOI(
	ctx context.Context,
	inputs POIEngineProofInputs,
	blindedCommitmentsOut []string,
	progress ProgressCallback,
) (Proof, PublicInputsPOI, error) {
	circuit := SelectPOICircuit(inputs)
	return p.ProvePOIForInputsOutputs(ctx, inputs, blindedCommitmentsOut, circuit.MaxInputs, circuit.MaxOutputs, progress)
}

func (p *Prover) ProvePOIForInputsOutputs(
	ctx context.Context,
	inputs POIEngineProofInputs,
	blindedCommitmentsOut []string,
	maxInputs int,
	maxOutputs int,
	progress ProgressCallback,
) (Proof, PublicInputsPOI, error) {
	if p.backend == nil {
		return Proof{}, PublicInputsPOI{}, ErrBackendNotConfigured
	}
	if p.artifactGetter == nil {
		return Proof{}, PublicInputsPOI{}, errors.New("artifact getter not configured")
	}

	formattedInputs, err := FormatPOIInputs(inputs, maxInputs, maxOutputs)
	if err != nil {
		return Proof{}, PublicInputsPOI{}, err
	}
	publicInputs, err := GetPublicInputsPOI(
		inputs.AnyRailgunTxidMerklerootAfterTransaction,
		blindedCommitmentsOut,
		inputs.POIMerkleRoots,
		inputs.RailgunTxidIfHasUnshield,
		maxInputs,
		maxOutputs,
	)
	if err != nil {
		return Proof{}, PublicInputsPOI{}, err
	}
	artifacts, err := p.artifactGetter.GetArtifactsPOI(ctx, maxInputs, maxOutputs)
	if err != nil {
		return Proof{}, PublicInputsPOI{}, err
	}
	circuit := CircuitID{
		Name:       "POI_" + formattedCircuitSuffix(maxInputs, maxOutputs),
		MaxInputs:  maxInputs,
		MaxOutputs: maxOutputs,
	}
	result, err := p.backend.ProvePOI(ctx, circuit, formattedInputs, artifacts, progress)
	if err != nil {
		return Proof{}, PublicInputsPOI{}, err
	}
	if err := AssertPublicSignalsMatch(BuildPublicSignalsPOI(publicInputs), result.PublicSignals); err != nil {
		return Proof{}, PublicInputsPOI{}, err
	}
	ok, err := p.backend.VerifyPOI(ctx, publicInputs, result.Proof, artifacts)
	if err != nil {
		return Proof{}, PublicInputsPOI{}, err
	}
	if !ok {
		return Proof{}, PublicInputsPOI{}, errors.New("poi proof verification failed")
	}
	return result.Proof, publicInputs, nil
}

func formattedCircuitSuffix(inputs int, outputs int) string {
	return fmt.Sprintf("%dX%d", inputs, outputs)
}
