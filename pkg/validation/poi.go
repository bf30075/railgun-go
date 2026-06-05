package validation

import (
	"fmt"
	"math/big"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
	"github.com/bf30075/railgun-go/pkg/txid"
)

type POIMerkleRootsValidator func(listKey string, poiMerkleRoots []string) (bool, error)

type POIProofVerifier func(transactProofData TransactProofData) (bool, error)

type TransactProofData struct {
	SnarkProof               railproof.Proof
	TxidMerkleRoot           string
	POIMerkleRoots           []string
	BlindedCommitmentsOut    []string
	RailgunTxidIfHasUnshield string
}

type PreTransactionPOIsPerTxidLeafPerList map[string]map[string]TransactProofData

func AssertIsValidSpendableTXID(
	listKey string,
	preTransactionPOIs PreTransactionPOIsPerTxidLeafPerList,
	railgunTxids []string,
	utxoTreesIn []*big.Int,
	validatePOIMerkleRoots POIMerkleRootsValidator,
	verifyProof POIProofVerifier,
) error {
	if len(railgunTxids) != len(utxoTreesIn) {
		return fmt.Errorf("railgunTxids length %d does not match utxoTreesIn length %d", len(railgunTxids), len(utxoTreesIn))
	}
	if validatePOIMerkleRoots == nil {
		return fmt.Errorf("poi merkle roots validator is required")
	}
	if verifyProof == nil {
		return fmt.Errorf("poi proof verifier is required")
	}

	txidLeafHashes := make([]string, len(railgunTxids))
	for i, railgunTxid := range railgunTxids {
		if utxoTreesIn[i] == nil || !utxoTreesIn[i].IsUint64() {
			return fmt.Errorf("utxoTreesIn[%d] must fit uint64", i)
		}
		railgunTxidBigInt, err := railcrypto.HexToBigInt(railgunTxid)
		if err != nil {
			return err
		}
		txidLeafHashes[i], err = txid.RailgunTxidLeafHash(
			railgunTxidBigInt,
			utxoTreesIn[i].Uint64(),
			railpoi.GlobalTreePositionPreTransactionPOIProof(),
		)
		if err != nil {
			return err
		}
	}

	poisForList, ok := preTransactionPOIs[listKey]
	if !ok {
		return fmt.Errorf("Missing POIs for list: %s", listKey)
	}

	for _, txidLeafHash := range txidLeafHashes {
		transactProofData, ok := poisForList[txidLeafHash]
		if !ok {
			return fmt.Errorf("Missing POI for txidLeafHash %s for list %s", txidLeafHash, listKey)
		}

		dummyMerkleProof, err := merkletree.CreateDummyProof(txidLeafHash)
		if err != nil {
			return err
		}
		if dummyMerkleProof.Root != transactProofData.TxidMerkleRoot {
			return fmt.Errorf("Invalid txid merkle proof")
		}

		validRoots, err := validatePOIMerkleRoots(listKey, transactProofData.POIMerkleRoots)
		if err != nil {
			return err
		}
		if !validRoots {
			return fmt.Errorf("Invalid POI merkleroots: list %s", listKey)
		}

		validProof, err := verifyProof(transactProofData)
		if err != nil {
			return err
		}
		if !validProof {
			return fmt.Errorf("Could not verify POI snark proof: list %s", listKey)
		}
	}

	return nil
}
