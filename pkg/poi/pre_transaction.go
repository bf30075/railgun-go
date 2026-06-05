package poi

import (
	"context"
	"fmt"
	"math/big"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
	"github.com/bf30075/railgun-go/pkg/txid"
)

const (
	GlobalUTXOTreePreTransactionPOIProof     uint64 = 199999
	GlobalUTXOPositionPreTransactionPOIProof uint64 = 199999
)

type PreTransactionUTXO struct {
	Tree              uint64
	Position          uint64
	TokenHash         string
	Random            string
	Value             *big.Int
	BlindedCommitment string
}

type PreTransactionPOIInputs struct {
	PublicInputs      railproof.PublicInputsRailgun
	PrivateInputs     railproof.PrivateInputsRailgun
	SpendingPublicKey [2]*big.Int
	NullifyingKey     *big.Int
	UTXOs             []PreTransactionUTXO
	POIMerkleProofs   []merkletree.MerkleProof
	TXIDMerkleProof   *merkletree.MerkleProof
	TreeNumber        uint64
	HasUnshield       bool
}

type PreparedPreTransactionPOI struct {
	TxidLeafHash             string
	TxidMerkleRoot           string
	POIMerkleRoots           []string
	BlindedCommitmentsIn     []string
	BlindedCommitmentsOut    []string
	RailgunTxidIfHasUnshield string
	ProofInputs              railproof.POIEngineProofInputs
	TxidMerkleProof          merkletree.MerkleProof
}

type PreTransactionPOI struct {
	SnarkProof               railproof.Proof
	TxidMerkleRoot           string
	POIMerkleRoots           []string
	BlindedCommitmentsOut    []string
	RailgunTxidIfHasUnshield string
}

type GeneratedPreTransactionPOI struct {
	PreparedPreTransactionPOI PreparedPreTransactionPOI
	PreTransactionPOI         PreTransactionPOI
	PublicInputs              railproof.PublicInputsPOI
}

type GenerateAndSubmitPreTransactionPOIRequest struct {
	TXIDVersion         string
	Chain               railchain.Chain
	ListKey             string
	TXIDMerkleRootIndex uint64
	Inputs              PreTransactionPOIInputs
	TXIDMerkleTree      txid.MerkleTreeStore
}

type SubmittedPreTransactionPOI struct {
	GeneratedPreTransactionPOI GeneratedPreTransactionPOI
	SubmitRequest              SubmitPOIRequest
}

type GenerateAndSubmitPreTransactionPOIsRequest struct {
	TXIDVersion         string
	Chain               railchain.Chain
	ListKeys            []string
	TXIDMerkleRootIndex uint64
	Inputs              PreTransactionPOIInputs
	TXIDMerkleTree      txid.MerkleTreeStore
}

func GlobalTreePositionPreTransactionPOIProof() *big.Int {
	return txid.GetGlobalTreePosition(
		GlobalUTXOTreePreTransactionPOIProof,
		GlobalUTXOPositionPreTransactionPOIProof,
	)
}

func PreparePreTransactionPOIInputs(inputs PreTransactionPOIInputs) (PreparedPreTransactionPOI, error) {
	if len(inputs.UTXOs) == 0 {
		return PreparedPreTransactionPOI{}, fmt.Errorf("at least one utxo is required")
	}
	if inputs.NullifyingKey == nil {
		return PreparedPreTransactionPOI{}, fmt.Errorf("nullifyingKey is required")
	}
	if inputs.SpendingPublicKey[0] == nil || inputs.SpendingPublicKey[1] == nil {
		return PreparedPreTransactionPOI{}, fmt.Errorf("spendingPublicKey is required")
	}

	blindedCommitmentsIn := make([]string, 0, len(inputs.UTXOs))
	for _, utxo := range inputs.UTXOs {
		if utxo.BlindedCommitment != "" {
			blindedCommitmentsIn = append(blindedCommitmentsIn, utxo.BlindedCommitment)
		}
	}
	if len(blindedCommitmentsIn) != len(inputs.PublicInputs.Nullifiers) {
		return PreparedPreTransactionPOI{}, fmt.Errorf(
			"not enough UTXO blinded commitments for railgun transaction nullifiers: expected %d, got %d",
			len(inputs.PublicInputs.Nullifiers),
			len(blindedCommitmentsIn),
		)
	}
	if len(inputs.POIMerkleProofs) != len(blindedCommitmentsIn) {
		return PreparedPreTransactionPOI{}, fmt.Errorf("expected %d POI merkle proofs, got %d", len(blindedCommitmentsIn), len(inputs.POIMerkleProofs))
	}
	for i, proof := range inputs.POIMerkleProofs {
		ok, err := merkletree.VerifyProof(proof)
		if err != nil {
			return PreparedPreTransactionPOI{}, fmt.Errorf("poi merkle proof[%d]: %w", i, err)
		}
		if !ok {
			return PreparedPreTransactionPOI{}, fmt.Errorf("invalid poi merkle proof[%d]", i)
		}
	}

	globalTreePosition := GlobalTreePositionPreTransactionPOIProof()
	railgunTxid, txidLeafHash, err := preTransactionTXIDLeafHash(inputs, globalTreePosition)
	if err != nil {
		return PreparedPreTransactionPOI{}, err
	}
	txidMerkleProof, err := txidMerkleProofForPreTransaction(txidLeafHash, inputs.TXIDMerkleProof)
	if err != nil {
		return PreparedPreTransactionPOI{}, err
	}
	ok, err := merkletree.VerifyProof(txidMerkleProof)
	if err != nil {
		return PreparedPreTransactionPOI{}, fmt.Errorf("txid merkle proof: %w", err)
	}
	if !ok {
		return PreparedPreTransactionPOI{}, fmt.Errorf("invalid txid merkle proof")
	}

	railgunTxidIfHasUnshield := "0x00"
	if inputs.HasUnshield {
		railgunTxidHex, err := railcrypto.BigIntToHex(railgunTxid, 32, false)
		if err != nil {
			return PreparedPreTransactionPOI{}, err
		}
		railgunTxidIfHasUnshield, err = railcrypto.BlindedUnshield(railgunTxidHex)
		if err != nil {
			return PreparedPreTransactionPOI{}, err
		}
	}

	nonUnshieldCommitments := inputs.PublicInputs.CommitmentsOut
	if inputs.HasUnshield && len(nonUnshieldCommitments) > 0 {
		nonUnshieldCommitments = nonUnshieldCommitments[:len(nonUnshieldCommitments)-1]
	}
	blindedCommitmentsOut := make([]string, len(nonUnshieldCommitments))
	for i, commitment := range nonUnshieldCommitments {
		if i >= len(inputs.PrivateInputs.NPKOut) || inputs.PrivateInputs.NPKOut[i] == nil {
			return PreparedPreTransactionPOI{}, fmt.Errorf("npkOut[%d] is required", i)
		}
		commitmentHex, err := railcrypto.BigIntToHex(commitment, 32, true)
		if err != nil {
			return PreparedPreTransactionPOI{}, err
		}
		position := new(big.Int).Add(globalTreePosition, new(big.Int).SetUint64(uint64(i)))
		blindedCommitmentsOut[i], err = railcrypto.BlindedCommitment(commitmentHex, inputs.PrivateInputs.NPKOut[i], position)
		if err != nil {
			return PreparedPreTransactionPOI{}, err
		}
	}

	poiRoots := make([]string, len(inputs.POIMerkleProofs))
	poiIndices := make([]string, len(inputs.POIMerkleProofs))
	poiElements := make([][]string, len(inputs.POIMerkleProofs))
	for i, proof := range inputs.POIMerkleProofs {
		poiRoots[i] = proof.Root
		poiIndices[i] = proof.Indices
		poiElements[i] = append([]string(nil), proof.Elements...)
	}

	proofInputs, err := buildProofInputs(inputs, globalTreePosition, txidMerkleProof, poiRoots, poiIndices, poiElements, railgunTxidIfHasUnshield)
	if err != nil {
		return PreparedPreTransactionPOI{}, err
	}
	return PreparedPreTransactionPOI{
		TxidLeafHash:             txidLeafHash,
		TxidMerkleRoot:           txidMerkleProof.Root,
		POIMerkleRoots:           poiRoots,
		BlindedCommitmentsIn:     blindedCommitmentsIn,
		BlindedCommitmentsOut:    blindedCommitmentsOut,
		RailgunTxidIfHasUnshield: railgunTxidIfHasUnshield,
		ProofInputs:              proofInputs,
		TxidMerkleProof:          txidMerkleProof,
	}, nil
}

func PreparePreTransactionPOIInputsWithTXIDMerkleTree(ctx context.Context, store txid.MerkleTreeStore, inputs PreTransactionPOIInputs) (PreparedPreTransactionPOI, error) {
	if store == nil {
		return PreparedPreTransactionPOI{}, fmt.Errorf("txid merkle tree store is required")
	}
	globalTreePosition := GlobalTreePositionPreTransactionPOIProof()
	_, txidLeafHash, err := preTransactionTXIDLeafHash(inputs, globalTreePosition)
	if err != nil {
		return PreparedPreTransactionPOI{}, err
	}
	proof, err := findTXIDMerkleProof(ctx, store, txidLeafHash)
	if err != nil {
		return PreparedPreTransactionPOI{}, err
	}
	inputs.TXIDMerkleProof = &proof
	return PreparePreTransactionPOIInputs(inputs)
}

func GeneratePreTransactionPOI(ctx context.Context, prover *railproof.Prover, inputs PreTransactionPOIInputs, progress railproof.ProgressCallback) (GeneratedPreTransactionPOI, error) {
	prepared, err := PreparePreTransactionPOIInputs(inputs)
	if err != nil {
		return GeneratedPreTransactionPOI{}, err
	}
	return generatePreparedPreTransactionPOI(ctx, prover, prepared, progress)
}

func generatePreparedPreTransactionPOI(ctx context.Context, prover *railproof.Prover, prepared PreparedPreTransactionPOI, progress railproof.ProgressCallback) (GeneratedPreTransactionPOI, error) {
	if prover == nil {
		return GeneratedPreTransactionPOI{}, fmt.Errorf("prover is required")
	}
	snarkProof, publicInputs, err := prover.ProvePOI(ctx, prepared.ProofInputs, prepared.BlindedCommitmentsOut, progress)
	if err != nil {
		return GeneratedPreTransactionPOI{}, err
	}
	return GeneratedPreTransactionPOI{
		PreparedPreTransactionPOI: prepared,
		PublicInputs:              publicInputs,
		PreTransactionPOI: PreTransactionPOI{
			SnarkProof:               snarkProof,
			TxidMerkleRoot:           prepared.TxidMerkleRoot,
			POIMerkleRoots:           append([]string(nil), prepared.POIMerkleRoots...),
			BlindedCommitmentsOut:    append([]string(nil), prepared.BlindedCommitmentsOut...),
			RailgunTxidIfHasUnshield: prepared.RailgunTxidIfHasUnshield,
		},
	}, nil
}

func GenerateAndSubmitPreTransactionPOI(ctx context.Context, manager *Manager, prover *railproof.Prover, request GenerateAndSubmitPreTransactionPOIRequest, progress railproof.ProgressCallback) (SubmittedPreTransactionPOI, error) {
	if manager == nil {
		return SubmittedPreTransactionPOI{}, fmt.Errorf("POI manager is required")
	}
	if request.TXIDVersion == "" {
		return SubmittedPreTransactionPOI{}, fmt.Errorf("txid version is required")
	}
	if request.ListKey == "" {
		return SubmittedPreTransactionPOI{}, fmt.Errorf("list key is required")
	}
	inputs := request.Inputs
	if len(inputs.POIMerkleProofs) == 0 {
		blindedCommitments := blindedCommitmentsForPreTransaction(inputs.UTXOs)
		proofs, err := manager.GetPOIMerkleProofs(ctx, request.TXIDVersion, request.Chain, request.ListKey, blindedCommitments)
		if err != nil {
			return SubmittedPreTransactionPOI{}, err
		}
		inputs.POIMerkleProofs = proofs
	}

	var prepared PreparedPreTransactionPOI
	var err error
	if request.TXIDMerkleTree != nil {
		prepared, err = PreparePreTransactionPOIInputsWithTXIDMerkleTree(ctx, request.TXIDMerkleTree, inputs)
	} else {
		prepared, err = PreparePreTransactionPOIInputs(inputs)
	}
	if err != nil {
		return SubmittedPreTransactionPOI{}, err
	}
	generated, err := generatePreparedPreTransactionPOI(ctx, prover, prepared, progress)
	if err != nil {
		return SubmittedPreTransactionPOI{}, err
	}
	submitRequest := SubmitPOIRequestFromPreTransaction(
		request.TXIDVersion,
		request.Chain,
		request.ListKey,
		request.TXIDMerkleRootIndex,
		generated.PreTransactionPOI,
	)
	if err := manager.SubmitPOI(ctx, submitRequest); err != nil {
		return SubmittedPreTransactionPOI{}, err
	}
	return SubmittedPreTransactionPOI{
		GeneratedPreTransactionPOI: generated,
		SubmitRequest:              submitRequest,
	}, nil
}

func GenerateAndSubmitPreTransactionPOIs(ctx context.Context, manager *Manager, prover *railproof.Prover, request GenerateAndSubmitPreTransactionPOIsRequest, progress railproof.ProgressCallback) ([]SubmittedPreTransactionPOI, error) {
	if len(request.ListKeys) == 0 {
		return nil, fmt.Errorf("at least one list key is required")
	}
	submitted := make([]SubmittedPreTransactionPOI, 0, len(request.ListKeys))
	for _, listKey := range request.ListKeys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := GenerateAndSubmitPreTransactionPOI(ctx, manager, prover, GenerateAndSubmitPreTransactionPOIRequest{
			TXIDVersion:         request.TXIDVersion,
			Chain:               request.Chain,
			ListKey:             listKey,
			TXIDMerkleRootIndex: request.TXIDMerkleRootIndex,
			Inputs:              request.Inputs,
			TXIDMerkleTree:      request.TXIDMerkleTree,
		}, progress)
		if err != nil {
			return nil, err
		}
		submitted = append(submitted, result)
	}
	return submitted, nil
}

func SubmitPOIRequestFromPreTransaction(txidVersion string, chain railchain.Chain, listKey string, txidMerkleRootIndex uint64, poi PreTransactionPOI) SubmitPOIRequest {
	return SubmitPOIRequest{
		TXIDVersion:              txidVersion,
		Chain:                    chain,
		ListKey:                  listKey,
		SnarkProof:               poi.SnarkProof,
		POIMerkleRoots:           append([]string(nil), poi.POIMerkleRoots...),
		TxidMerkleRoot:           poi.TxidMerkleRoot,
		TxidMerkleRootIndex:      txidMerkleRootIndex,
		BlindedCommitmentsOut:    append([]string(nil), poi.BlindedCommitmentsOut...),
		RailgunTxidIfHasUnshield: poi.RailgunTxidIfHasUnshield,
	}
}

func SubmitPreTransactionPOI(ctx context.Context, manager *Manager, txidVersion string, chain railchain.Chain, listKey string, txidMerkleRootIndex uint64, poi PreTransactionPOI) error {
	if manager == nil {
		return fmt.Errorf("POI manager is required")
	}
	return manager.SubmitPOI(ctx, SubmitPOIRequestFromPreTransaction(txidVersion, chain, listKey, txidMerkleRootIndex, poi))
}

func preTransactionTXIDLeafHash(inputs PreTransactionPOIInputs, globalTreePosition *big.Int) (*big.Int, string, error) {
	railgunTxid, err := txid.RailgunTransactionIDFromBigInts(
		inputs.PublicInputs.Nullifiers,
		inputs.PublicInputs.CommitmentsOut,
		inputs.PublicInputs.BoundParamsHash,
	)
	if err != nil {
		return nil, "", err
	}
	txidLeafHash, err := txid.RailgunTxidLeafHash(railgunTxid, inputs.TreeNumber, globalTreePosition)
	if err != nil {
		return nil, "", err
	}
	return railgunTxid, txidLeafHash, nil
}

func txidMerkleProofForPreTransaction(txidLeafHash string, proof *merkletree.MerkleProof) (merkletree.MerkleProof, error) {
	if proof == nil {
		return merkletree.CreateDummyProof(txidLeafHash)
	}
	if !sameHex(proof.Leaf, txidLeafHash) {
		return merkletree.MerkleProof{}, fmt.Errorf("txid merkle proof leaf does not match txid leaf hash")
	}
	return cloneMerkleProof(*proof), nil
}

func findTXIDMerkleProof(ctx context.Context, store txid.MerkleTreeStore, txidLeafHash string) (merkletree.MerkleProof, error) {
	leaves, err := store.ListLeaves(ctx)
	if err != nil {
		return merkletree.MerkleProof{}, err
	}
	for _, leaf := range leaves {
		if !sameHex(leaf.Hash, txidLeafHash) {
			continue
		}
		return store.Proof(ctx, leaf.Tree, leaf.Index)
	}
	return merkletree.MerkleProof{}, fmt.Errorf("txid merkle leaf not found")
}

func blindedCommitmentsForPreTransaction(utxos []PreTransactionUTXO) []string {
	out := []string{}
	for _, utxo := range utxos {
		if utxo.BlindedCommitment != "" {
			out = append(out, utxo.BlindedCommitment)
		}
	}
	return out
}

func buildProofInputs(
	inputs PreTransactionPOIInputs,
	globalTreePosition *big.Int,
	txidMerkleProof merkletree.MerkleProof,
	poiRoots []string,
	poiIndices []string,
	poiElements [][]string,
	railgunTxidIfHasUnshield string,
) (railproof.POIEngineProofInputs, error) {
	boundParamsHash, err := railcrypto.BigIntToHex(inputs.PublicInputs.BoundParamsHash, 32, true)
	if err != nil {
		return railproof.POIEngineProofInputs{}, err
	}
	nullifiers, err := hexBigIntSlice(inputs.PublicInputs.Nullifiers)
	if err != nil {
		return railproof.POIEngineProofInputs{}, err
	}
	commitmentsOut, err := hexBigIntSlice(inputs.PublicInputs.CommitmentsOut)
	if err != nil {
		return railproof.POIEngineProofInputs{}, err
	}
	valuesIn := make([]*big.Int, len(inputs.UTXOs))
	randomsIn := make([]string, len(inputs.UTXOs))
	positionsIn := make([]uint64, len(inputs.UTXOs))
	for i, utxo := range inputs.UTXOs {
		if utxo.Value == nil {
			return railproof.POIEngineProofInputs{}, fmt.Errorf("utxo[%d].value is required", i)
		}
		valuesIn[i] = cloneBigInt(utxo.Value)
		randomsIn[i] = utxo.Random
		positionsIn[i] = utxo.Position
	}
	return railproof.POIEngineProofInputs{
		AnyRailgunTxidMerklerootAfterTransaction: txidMerkleProof.Root,
		BoundParamsHash:                          boundParamsHash,
		Nullifiers:                               nullifiers,
		CommitmentsOut:                           commitmentsOut,
		SpendingPublicKey:                        [2]*big.Int{cloneBigInt(inputs.SpendingPublicKey[0]), cloneBigInt(inputs.SpendingPublicKey[1])},
		NullifyingKey:                            cloneBigInt(inputs.NullifyingKey),
		Token:                                    inputs.UTXOs[0].TokenHash,
		RandomsIn:                                randomsIn,
		ValuesIn:                                 valuesIn,
		UTXOPositionsIn:                          positionsIn,
		UTXOTreeIn:                               inputs.UTXOs[0].Tree,
		NPKsOut:                                  cloneBigIntSlice(inputs.PrivateInputs.NPKOut),
		ValuesOut:                                cloneBigIntSlice(inputs.PrivateInputs.ValueOut),
		UTXOBatchGlobalStartPositionOut:          cloneBigInt(globalTreePosition),
		RailgunTxidIfHasUnshield:                 railgunTxidIfHasUnshield,
		RailgunTxidMerkleProofIndices:            txidMerkleProof.Indices,
		RailgunTxidMerkleProofPathElements:       append([]string(nil), txidMerkleProof.Elements...),
		POIMerkleRoots:                           append([]string(nil), poiRoots...),
		POIInMerkleProofIndices:                  append([]string(nil), poiIndices...),
		POIInMerkleProofPathElements:             cloneStringRows(poiElements),
	}, nil
}

func hexBigIntSlice(values []*big.Int) ([]string, error) {
	out := make([]string, len(values))
	for i, value := range values {
		var err error
		out[i], err = railcrypto.BigIntToHex(value, 32, true)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func cloneBigIntSlice(values []*big.Int) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = cloneBigInt(value)
	}
	return out
}

func cloneStringRows(values [][]string) [][]string {
	out := make([][]string, len(values))
	for i, row := range values {
		out[i] = append([]string(nil), row...)
	}
	return out
}

func cloneMerkleProof(proof merkletree.MerkleProof) merkletree.MerkleProof {
	proof.Elements = append([]string(nil), proof.Elements...)
	return proof
}

func sameHex(a string, b string) bool {
	left, err := railcrypto.HexToBigInt(a)
	if err != nil {
		return false
	}
	right, err := railcrypto.HexToBigInt(b)
	if err != nil {
		return false
	}
	return left.Cmp(right) == 0
}
