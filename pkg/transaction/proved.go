package transaction

import (
	"context"
	"math/big"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/proof"
)

const zeroAddress = "0x0000000000000000000000000000000000000000"

func ZeroProof() proof.Proof {
	return proof.Proof{
		PiA: [2]string{"00", "00"},
		PiB: [2][2]string{{"00", "00"}, {"00", "00"}},
		PiC: [2]string{"00", "00"},
	}
}

func EmptyUnshieldPreimage() CommitmentPreimage {
	tokenData, _ := railcrypto.TokenDataERC20(zeroAddress)
	return CommitmentPreimage{
		NPK:   zeroAddress,
		Token: tokenData,
		Value: big.NewInt(0),
	}
}

func CreateDummyProvedTransactionV2(request TransactionRequestV2) (TransactionStructV2, error) {
	return CreateDummyProvedTransactionV2WithUnshield(request, EmptyUnshieldPreimage())
}

func CreateDummyProvedTransactionV2WithUnshield(request TransactionRequestV2, unshieldPreimage CommitmentPreimage) (TransactionStructV2, error) {
	return CreateTransactionStructV2(
		ZeroProof(),
		request.PublicInputs,
		request.BoundParams,
		unshieldPreimage,
	)
}

func CreateDummyProvedTransactionV3(request TransactionRequestV3) (TransactionStructV3, error) {
	return CreateDummyProvedTransactionV3WithUnshield(request, EmptyUnshieldPreimage())
}

func CreateDummyProvedTransactionV3WithUnshield(request TransactionRequestV3, unshieldPreimage CommitmentPreimage) (TransactionStructV3, error) {
	return CreateTransactionStructV3(
		ZeroProof(),
		request.PublicInputs,
		request.BoundParams,
		unshieldPreimage,
	)
}

func ProveUnprovedTransactionV2(ctx context.Context, prover *proof.Prover, unproved UnprovedTransactionV2, progress proof.ProgressCallback) (TransactionStructV2, error) {
	snarkProof, publicInputs, err := prover.ProveRailgun(ctx, unproved.ProofInputs(), progress)
	if err != nil {
		return TransactionStructV2{}, err
	}
	return CreateTransactionStructV2(
		snarkProof,
		publicInputs,
		unproved.Request.BoundParams,
		defaultUnshieldPreimage(unproved.UnshieldPreimage),
	)
}

func ProveUnprovedTransactionV3(ctx context.Context, prover *proof.Prover, unproved UnprovedTransactionV3, progress proof.ProgressCallback) (TransactionStructV3, error) {
	snarkProof, publicInputs, err := prover.ProveRailgun(ctx, unproved.ProofInputs(), progress)
	if err != nil {
		return TransactionStructV3{}, err
	}
	return CreateTransactionStructV3(
		snarkProof,
		publicInputs,
		unproved.Request.BoundParams,
		defaultUnshieldPreimage(unproved.UnshieldPreimage),
	)
}

func defaultUnshieldPreimage(preimage CommitmentPreimage) CommitmentPreimage {
	if preimage.Value == nil {
		return EmptyUnshieldPreimage()
	}
	return preimage
}
