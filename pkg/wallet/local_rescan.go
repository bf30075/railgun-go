package wallet

import (
	"context"
	"fmt"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
)

type LocalRescanOptions struct {
	TXIDVersions []string
}

func (wallet *Wallet) RescanLocalUTXOTree(ctx context.Context, options LocalRescanOptions) (ImportSummary, error) {
	if err := wallet.validate(); err != nil {
		return ImportSummary{}, err
	}
	if wallet.UTXOMerkleTree == nil {
		return ImportSummary{}, fmt.Errorf("utxo merkle tree store is required")
	}
	versions := options.TXIDVersions
	if len(versions) == 0 {
		versions = []string{railcrypto.TXIDVersionV2PoseidonMerkle, railcrypto.TXIDVersionV3PoseidonMerkle}
	}
	summary := ImportSummary{}
	for _, version := range versions {
		switch version {
		case railcrypto.TXIDVersionV2PoseidonMerkle:
			part, err := rescanLocalV2Commitments(ctx, wallet.State, wallet.SpentPOIEvents, wallet.UTXOMerkleTree, wallet.Keys)
			if err != nil {
				return ImportSummary{}, err
			}
			addImportSummary(&summary, part)
		case railcrypto.TXIDVersionV3PoseidonMerkle:
			part, err := rescanLocalV3Commitments(ctx, wallet.State, wallet.SpentPOIEvents, wallet.UTXOMerkleTree, wallet.Keys)
			if err != nil {
				return ImportSummary{}, err
			}
			addImportSummary(&summary, part)
		default:
			return ImportSummary{}, fmt.Errorf("unsupported txid version %s", version)
		}
	}
	part, err := rescanLocalUnshieldEvents(ctx, wallet.SpentPOIEvents, wallet.UTXOMerkleTree)
	if err != nil {
		return ImportSummary{}, err
	}
	addImportSummary(&summary, part)
	part, err = markLocalRescanNullifiersSpent(ctx, wallet.State, wallet.UTXOMerkleTree)
	if err != nil {
		return ImportSummary{}, err
	}
	addImportSummary(&summary, part)
	return summary, nil
}

func rescanLocalV2Commitments(ctx context.Context, store StateStore, spentPOIEvents SpentPOIEventStore, utxoTree railutxotree.Store, keys ScanKeys) (ImportSummary, error) {
	reader, ok := utxoTree.(railutxotree.V2CommitmentReader)
	if !ok {
		return ImportSummary{}, fmt.Errorf("utxo merkle tree store does not support V2 commitment reads")
	}
	commitments, err := reader.ListV2Commitments(ctx)
	if err != nil {
		return ImportSummary{}, err
	}
	summary := ImportSummary{}
	for _, commitment := range commitments {
		if err := ctx.Err(); err != nil {
			return ImportSummary{}, err
		}
		txo, isSent, ok, err := txoFromV2CommitmentWithDirection(keys, commitment)
		if err != nil {
			return ImportSummary{}, err
		}
		if !ok {
			summary.CommitmentsSkipped++
			continue
		}
		if isSent {
			if spentPOIEvents != nil {
				railgunTxid := firstNonEmpty(commitment.RailgunTxid, txo.TXID)
				if err := spentPOIEvents.UpsertSentCommitmentPOIEvent(ctx, sentCommitmentPOIStatusFromTXO(txo, commitment.Txid, railgunTxid)); err != nil {
					return ImportSummary{}, err
				}
				summary.SentCommitmentPOIEventsIndexed++
			}
			continue
		}
		if err := store.UpsertTXO(ctx, txo); err != nil {
			return ImportSummary{}, err
		}
		summary.TXOsImported++
	}
	return summary, nil
}

func rescanLocalV3Commitments(ctx context.Context, store StateStore, spentPOIEvents SpentPOIEventStore, utxoTree railutxotree.Store, keys ScanKeys) (ImportSummary, error) {
	reader, ok := utxoTree.(railutxotree.V3CommitmentReader)
	if !ok {
		return ImportSummary{}, fmt.Errorf("utxo merkle tree store does not support V3 commitment reads")
	}
	commitments, err := reader.ListV3Commitments(ctx)
	if err != nil {
		return ImportSummary{}, err
	}
	summary := ImportSummary{}
	for _, commitment := range commitments {
		if err := ctx.Err(); err != nil {
			return ImportSummary{}, err
		}
		txo, isSent, ok, err := txoFromV3CommitmentWithDirection(keys, commitment)
		if err != nil {
			return ImportSummary{}, err
		}
		if !ok {
			summary.CommitmentsSkipped++
			continue
		}
		if isSent {
			if spentPOIEvents != nil {
				railgunTxid := firstNonEmpty(commitment.RailgunTxid, txo.TXID)
				if err := spentPOIEvents.UpsertSentCommitmentPOIEvent(ctx, sentCommitmentPOIStatusFromTXO(txo, commitment.Txid, railgunTxid)); err != nil {
					return ImportSummary{}, err
				}
				summary.SentCommitmentPOIEventsIndexed++
			}
			continue
		}
		if err := store.UpsertTXO(ctx, txo); err != nil {
			return ImportSummary{}, err
		}
		summary.TXOsImported++
	}
	return summary, nil
}

func rescanLocalUnshieldEvents(ctx context.Context, spentPOIEvents SpentPOIEventStore, utxoTree railutxotree.Store) (ImportSummary, error) {
	if spentPOIEvents == nil {
		return ImportSummary{}, nil
	}
	reader, ok := utxoTree.(railutxotree.UnshieldEventReader)
	if !ok {
		return ImportSummary{}, nil
	}
	events, err := reader.ListUnshieldEvents(ctx)
	if err != nil {
		return ImportSummary{}, err
	}
	summary := ImportSummary{}
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return ImportSummary{}, err
		}
		if err := spentPOIEvents.UpsertUnshieldPOIEvent(ctx, unshieldPOIStatusFromV2Event(event)); err != nil {
			return ImportSummary{}, err
		}
		summary.UnshieldPOIEventsIndexed++
	}
	return summary, nil
}

func markLocalRescanNullifiersSpent(ctx context.Context, store StateStore, utxoTree railutxotree.Store) (ImportSummary, error) {
	reader, ok := utxoTree.(railutxotree.NullifierReader)
	if !ok {
		return ImportSummary{}, nil
	}
	nullifiers, err := reader.ListNullifiers(ctx)
	if err != nil {
		return ImportSummary{}, err
	}
	txos, err := store.ListTXOs(ctx)
	if err != nil {
		return ImportSummary{}, err
	}
	owned := make(map[string]struct{}, len(txos))
	for _, txo := range txos {
		nullifier, err := railcrypto.FormatHexToByteLength(txo.Nullifier, 32, false)
		if err != nil {
			return ImportSummary{}, fmt.Errorf("txo nullifier: %w", err)
		}
		owned[nullifier] = struct{}{}
	}
	summary := ImportSummary{}
	for _, event := range nullifiers {
		if err := ctx.Err(); err != nil {
			return ImportSummary{}, err
		}
		nullifier, err := railcrypto.FormatHexToByteLength(event.Nullifier, 32, false)
		if err != nil {
			return ImportSummary{}, fmt.Errorf("nullifier: %w", err)
		}
		if _, ok := owned[nullifier]; !ok {
			continue
		}
		if reorgStore, ok := store.(ReorgStateStore); ok {
			err = reorgStore.MarkTXOSpentAtBlock(ctx, nullifier, event.Txid, event.BlockNumber)
		} else {
			err = store.MarkTXOSpent(ctx, nullifier, event.Txid)
		}
		if err != nil {
			summary.SpendsSkipped++
			continue
		}
		summary.SpendsMarked++
	}
	return summary, nil
}

func addImportSummary(total *ImportSummary, part ImportSummary) {
	total.TXOsImported += part.TXOsImported
	total.CommitmentsSkipped += part.CommitmentsSkipped
	total.SpendsMarked += part.SpendsMarked
	total.SpendsSkipped += part.SpendsSkipped
	total.RailgunTransactionsIndexed += part.RailgunTransactionsIndexed
	total.TXIDMerkleLeavesIndexed += part.TXIDMerkleLeavesIndexed
	total.UTXOMerkleLeavesIndexed += part.UTXOMerkleLeavesIndexed
	total.NullifierEventsIndexed += part.NullifierEventsIndexed
	total.UnshieldEventsIndexed += part.UnshieldEventsIndexed
	total.SentCommitmentPOIEventsIndexed += part.SentCommitmentPOIEventsIndexed
	total.UnshieldPOIEventsIndexed += part.UnshieldPOIEventsIndexed
}
