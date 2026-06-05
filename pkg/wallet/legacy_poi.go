package wallet

import (
	"context"
	"fmt"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
)

type SubmitLegacyTransactPOIEventsSummary struct {
	TXOsChecked         int
	TXOsMatched         int
	TXIDIndicesMissing  int
	ProofDatasSubmitted int
	ListKeysSubmitted   []string
}

type SubmitLegacyTransactPOIEventsAndRefreshSummary struct {
	Submit  SubmitLegacyTransactPOIEventsSummary
	Refresh RefreshPOIsSummary
}

func SubmitLegacyTransactPOIEvents(ctx context.Context, store StateStore, poiManager *railpoi.Manager, txidMerkleTree railtxid.MerkleTreeStore, txidVersion string, chain railchain.Chain) (SubmitLegacyTransactPOIEventsSummary, error) {
	if store == nil {
		return SubmitLegacyTransactPOIEventsSummary{}, fmt.Errorf("state store is required")
	}
	if poiManager == nil {
		return SubmitLegacyTransactPOIEventsSummary{}, fmt.Errorf("poi manager is required")
	}
	if txidMerkleTree == nil {
		return SubmitLegacyTransactPOIEventsSummary{}, fmt.Errorf("txid merkle tree store is required")
	}
	if txidVersion == "" {
		return SubmitLegacyTransactPOIEventsSummary{}, fmt.Errorf("txid version is required")
	}
	txos, err := store.ListTXOs(ctx)
	if err != nil {
		return SubmitLegacyTransactPOIEventsSummary{}, err
	}
	txos = txosForTXIDVersion(txos, txidVersion)
	summary := SubmitLegacyTransactPOIEventsSummary{TXOsChecked: len(txos)}
	candidates := []StoredTXO{}
	for _, txo := range txos {
		if poiManager.ShouldSubmitLegacyTransactEventsTXO(chain, storedTXOToPOITXO(txo)) {
			candidates = append(candidates, txo)
		}
	}
	summary.TXOsMatched = len(candidates)
	if len(candidates) == 0 {
		return summary, nil
	}

	leavesByRailgunTxid, err := txidLeavesByRailgunTxid(ctx, txidMerkleTree)
	if err != nil {
		return SubmitLegacyTransactPOIEventsSummary{}, err
	}
	proofDatas := []railpoi.LegacyTransactProofData{}
	for _, txo := range candidates {
		leaf, ok := leavesByRailgunTxid[txo.TransactCreationRailgunTxid]
		if !ok {
			summary.TXIDIndicesMissing++
			continue
		}
		proofData, err := legacyTransactProofDataFromTXO(txo, leaf)
		if err != nil {
			return SubmitLegacyTransactPOIEventsSummary{}, err
		}
		proofDatas = append(proofDatas, proofData)
	}
	if len(proofDatas) == 0 {
		return summary, nil
	}

	listKeys := poiManager.GetListKeysCanSubmitLegacyTransactEvents(poiTXOsFromStored(txos))
	if len(listKeys) == 0 {
		return summary, nil
	}
	if err := poiManager.SubmitLegacyTransactProofs(ctx, railpoi.SubmitLegacyTransactProofsRequest{
		TXIDVersion:              txidVersion,
		Chain:                    chain,
		ListKeys:                 listKeys,
		LegacyTransactProofDatas: proofDatas,
	}); err != nil {
		return SubmitLegacyTransactPOIEventsSummary{}, err
	}
	summary.ProofDatasSubmitted = len(proofDatas)
	summary.ListKeysSubmitted = append([]string(nil), listKeys...)
	return summary, nil
}

func (wallet *Wallet) SubmitLegacyTransactPOIEvents(ctx context.Context, txidVersion string, chain railchain.Chain) (SubmitLegacyTransactPOIEventsSummary, error) {
	if err := wallet.validate(); err != nil {
		return SubmitLegacyTransactPOIEventsSummary{}, err
	}
	return SubmitLegacyTransactPOIEvents(ctx, wallet.State, wallet.POIManager, wallet.TXIDMerkleTree, txidVersion, chain)
}

func SubmitLegacyTransactPOIEventsAndRefresh(ctx context.Context, store StateStore, poiManager *railpoi.Manager, txidMerkleTree railtxid.MerkleTreeStore, txidVersion string, chain railchain.Chain) (SubmitLegacyTransactPOIEventsAndRefreshSummary, error) {
	submit, err := SubmitLegacyTransactPOIEvents(ctx, store, poiManager, txidMerkleTree, txidVersion, chain)
	if err != nil {
		return SubmitLegacyTransactPOIEventsAndRefreshSummary{}, err
	}
	summary := SubmitLegacyTransactPOIEventsAndRefreshSummary{Submit: submit}
	if submit.TXOsMatched == 0 {
		return summary, nil
	}
	refresh, err := RefreshPOIs(ctx, store, poiManager, txidVersion, chain)
	if err != nil {
		return SubmitLegacyTransactPOIEventsAndRefreshSummary{}, err
	}
	summary.Refresh = refresh
	return summary, nil
}

func (wallet *Wallet) SubmitLegacyTransactPOIEventsAndRefresh(ctx context.Context, txidVersion string, chain railchain.Chain) (SubmitLegacyTransactPOIEventsAndRefreshSummary, error) {
	if err := wallet.validate(); err != nil {
		return SubmitLegacyTransactPOIEventsAndRefreshSummary{}, err
	}
	return SubmitLegacyTransactPOIEventsAndRefresh(ctx, wallet.State, wallet.POIManager, wallet.TXIDMerkleTree, txidVersion, chain)
}

func txidLeavesByRailgunTxid(ctx context.Context, store railtxid.MerkleTreeStore) (map[string]railtxid.MerkleLeaf, error) {
	leaves, err := store.ListLeaves(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]railtxid.MerkleLeaf, len(leaves))
	for _, leaf := range leaves {
		if leaf.RailgunTxid != "" {
			out[leaf.RailgunTxid] = leaf
		}
	}
	return out, nil
}

func legacyTransactProofDataFromTXO(txo StoredTXO, leaf railtxid.MerkleLeaf) (railpoi.LegacyTransactProofData, error) {
	if txo.NotePublicKey == "" {
		return railpoi.LegacyTransactProofData{}, fmt.Errorf("txo %s note public key is required", txo.Nullifier)
	}
	if txo.Value == nil {
		return railpoi.LegacyTransactProofData{}, fmt.Errorf("txo %s value is required", txo.Nullifier)
	}
	npk, err := railcrypto.FormatHexToByteLength(txo.NotePublicKey, 32, true)
	if err != nil {
		return railpoi.LegacyTransactProofData{}, fmt.Errorf("txo %s note public key: %w", txo.Nullifier, err)
	}
	return railpoi.LegacyTransactProofData{
		TXIDIndex:         railtxid.GetGlobalTreePosition(leaf.Tree, leaf.Index).String(),
		NPK:               npk,
		Value:             txo.Value.String(),
		TokenHash:         txo.TokenHash,
		BlindedCommitment: txo.BlindedCommitment,
	}, nil
}

func txosForTXIDVersion(txos []StoredTXO, txidVersion string) []StoredTXO {
	out := []StoredTXO{}
	for _, txo := range txos {
		if txo.TXIDVersion != "" && txo.TXIDVersion != txidVersion {
			continue
		}
		out = append(out, txo)
	}
	return out
}
