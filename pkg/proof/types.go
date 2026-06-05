package proof

import (
	"context"
	"math/big"
)

type ProgressCallback func(progress float64)

type Artifact struct {
	WASM []byte
	ZKey []byte
	DAT  []byte
	VKey any
}

type ArtifactGetter interface {
	AssertArtifactExists(nullifiers int, commitments int) error
	GetArtifacts(ctx context.Context, publicInputs PublicInputsRailgun) (Artifact, error)
	GetArtifactsPOI(ctx context.Context, maxInputs int, maxOutputs int) (Artifact, error)
}

type G1Point struct {
	X *big.Int
	Y *big.Int
}

type G2Point struct {
	X [2]*big.Int
	Y [2]*big.Int
}

type SnarkProof struct {
	A G1Point
	B G2Point
	C G1Point
}

type Proof struct {
	PiA [2]string    `json:"pi_a"`
	PiB [2][2]string `json:"pi_b"`
	PiC [2]string    `json:"pi_c"`
}

type ProofResult struct {
	Proof         Proof
	PublicSignals []*big.Int
}

type PublicInputsRailgun struct {
	MerkleRoot      *big.Int
	BoundParamsHash *big.Int
	Nullifiers      []*big.Int
	CommitmentsOut  []*big.Int
}

type PrivateInputsRailgun struct {
	TokenAddress  *big.Int
	PublicKey     [2]*big.Int
	RandomIn      []*big.Int
	ValueIn       []*big.Int
	PathElements  [][]*big.Int
	LeavesIndices []*big.Int
	NullifyingKey *big.Int
	NPKOut        []*big.Int
	ValueOut      []*big.Int
}

type UnprovedTransactionInputs struct {
	PublicInputs  PublicInputsRailgun
	PrivateInputs PrivateInputsRailgun
	Signature     [3]*big.Int
}

type FormattedCircuitInputsRailgun struct {
	MerkleRoot      *big.Int
	BoundParamsHash *big.Int
	Nullifiers      []*big.Int
	CommitmentsOut  []*big.Int
	Token           *big.Int
	PublicKey       []*big.Int
	Signature       []*big.Int
	RandomIn        []*big.Int
	ValueIn         []*big.Int
	PathElements    []*big.Int
	LeavesIndices   []*big.Int
	NullifyingKey   *big.Int
	NPKOut          []*big.Int
	ValueOut        []*big.Int
}

type PublicInputsPOI struct {
	AnyRailgunTxidMerklerootAfterTransaction *big.Int
	BlindedCommitmentsOut                    []*big.Int
	POIMerkleRoots                           []*big.Int
	RailgunTxidIfHasUnshield                 *big.Int
}

type POIEngineProofInputs struct {
	AnyRailgunTxidMerklerootAfterTransaction string
	POIMerkleRoots                           []string
	BoundParamsHash                          string
	Nullifiers                               []string
	CommitmentsOut                           []string
	SpendingPublicKey                        [2]*big.Int
	NullifyingKey                            *big.Int
	Token                                    string
	RandomsIn                                []string
	ValuesIn                                 []*big.Int
	UTXOPositionsIn                          []uint64
	UTXOTreeIn                               uint64
	NPKsOut                                  []*big.Int
	ValuesOut                                []*big.Int
	UTXOBatchGlobalStartPositionOut          *big.Int
	RailgunTxidIfHasUnshield                 string
	RailgunTxidMerkleProofIndices            string
	RailgunTxidMerkleProofPathElements       []string
	POIInMerkleProofIndices                  []string
	POIInMerkleProofPathElements             [][]string
}

type FormattedCircuitInputsPOI struct {
	AnyRailgunTxidMerklerootAfterTransaction *big.Int
	POIMerkleRoots                           []*big.Int
	BoundParamsHash                          *big.Int
	Nullifiers                               []*big.Int
	CommitmentsOut                           []*big.Int
	SpendingPublicKey                        [2]*big.Int
	NullifyingKey                            *big.Int
	Token                                    *big.Int
	RandomsIn                                []*big.Int
	ValuesIn                                 []*big.Int
	UTXOPositionsIn                          []*big.Int
	UTXOTreeIn                               *big.Int
	NPKsOut                                  []*big.Int
	ValuesOut                                []*big.Int
	UTXOBatchGlobalStartPositionOut          *big.Int
	RailgunTxidIfHasUnshield                 *big.Int
	RailgunTxidMerkleProofIndices            *big.Int
	RailgunTxidMerkleProofPathElements       []*big.Int
	POIInMerkleProofIndices                  []*big.Int
	POIInMerkleProofPathElements             [][]*big.Int
}

type NativeFormattedCircuitInputsRailgun struct {
	MerkleRoot      string   `json:"merkleRoot"`
	BoundParamsHash string   `json:"boundParamsHash"`
	Nullifiers      []string `json:"nullifiers"`
	CommitmentsOut  []string `json:"commitmentsOut"`
	Token           string   `json:"token"`
	PublicKey       []string `json:"publicKey"`
	Signature       []string `json:"signature"`
	RandomIn        []string `json:"randomIn"`
	ValueIn         []string `json:"valueIn"`
	PathElements    []string `json:"pathElements"`
	LeavesIndices   []string `json:"leavesIndices"`
	NullifyingKey   string   `json:"nullifyingKey"`
	NPKOut          []string `json:"npkOut"`
	ValueOut        []string `json:"valueOut"`
}

type NativeFormattedCircuitInputsPOI struct {
	AnyRailgunTxidMerklerootAfterTransaction string     `json:"anyRailgunTxidMerklerootAfterTransaction"`
	POIMerkleRoots                           []string   `json:"poiMerkleroots"`
	BoundParamsHash                          string     `json:"boundParamsHash"`
	Nullifiers                               []string   `json:"nullifiers"`
	CommitmentsOut                           []string   `json:"commitmentsOut"`
	SpendingPublicKey                        [2]string  `json:"spendingPublicKey"`
	NullifyingKey                            string     `json:"nullifyingKey"`
	Token                                    string     `json:"token"`
	RandomsIn                                []string   `json:"randomsIn"`
	ValuesIn                                 []string   `json:"valuesIn"`
	UTXOPositionsIn                          []string   `json:"utxoPositionsIn"`
	UTXOTreeIn                               string     `json:"utxoTreeIn"`
	NPKsOut                                  []string   `json:"npksOut"`
	ValuesOut                                []string   `json:"valuesOut"`
	UTXOBatchGlobalStartPositionOut          string     `json:"utxoBatchGlobalStartPositionOut"`
	RailgunTxidIfHasUnshield                 string     `json:"railgunTxidIfHasUnshield"`
	RailgunTxidMerkleProofIndices            string     `json:"railgunTxidMerkleProofIndices"`
	RailgunTxidMerkleProofPathElements       []string   `json:"railgunTxidMerkleProofPathElements"`
	POIInMerkleProofIndices                  []string   `json:"poiInMerkleProofIndices"`
	POIInMerkleProofPathElements             [][]string `json:"poiInMerkleProofPathElements"`
}
