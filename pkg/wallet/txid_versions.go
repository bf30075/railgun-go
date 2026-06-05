package wallet

import (
	"context"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

type TokenBalancesAllTXIDVersions map[string]TokenBalances

func ActiveTXIDVersions(chain railchain.Chain) []string {
	versions := []string{railcrypto.TXIDVersionV2PoseidonMerkle}
	if railchain.SupportsV3(chain) {
		versions = append(versions, railcrypto.TXIDVersionV3PoseidonMerkle)
	}
	return versions
}

// BalancesAllTXIDVersions 返回某条链全局 active TXID version 的余额。
func (wallet *Wallet) BalancesAllTXIDVersions(ctx context.Context, chain railchain.Chain, includedBuckets []string) (TokenBalancesAllTXIDVersions, error) {
	return wallet.BalancesForTXIDVersions(ctx, ActiveTXIDVersions(chain), includedBuckets)
}

// BalancesForTXIDVersions 返回显式 TXID version 列表对应的余额。
func (wallet *Wallet) BalancesForTXIDVersions(ctx context.Context, txidVersions []string, includedBuckets []string) (TokenBalancesAllTXIDVersions, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	out := TokenBalancesAllTXIDVersions{}
	for _, txidVersion := range txidVersions {
		balances, err := wallet.BalancesForTXIDVersion(ctx, txidVersion, includedBuckets)
		if err != nil {
			return nil, err
		}
		if len(balances) > 0 {
			out[txidVersion] = balances
		}
	}
	return out, nil
}

// SpendableBalancesAllTXIDVersions 返回某条链全局 active TXID version 的可花费余额。
func (wallet *Wallet) SpendableBalancesAllTXIDVersions(ctx context.Context, chain railchain.Chain) (TokenBalancesAllTXIDVersions, error) {
	return wallet.SpendableBalancesForTXIDVersions(ctx, chain, ActiveTXIDVersions(chain))
}

// SpendableBalancesForTXIDVersions 返回显式 TXID version 列表对应的可花费余额。
func (wallet *Wallet) SpendableBalancesForTXIDVersions(ctx context.Context, chain railchain.Chain, txidVersions []string) (TokenBalancesAllTXIDVersions, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	buckets, err := wallet.POIManager.GetSpendableBalanceBuckets(ctx, chain)
	if err != nil {
		return nil, err
	}
	return wallet.BalancesForTXIDVersions(ctx, txidVersions, buckets)
}

// TransactionHistoryAllTXIDVersions 返回某条链全局 active TXID version 的交易历史。
func (wallet *Wallet) TransactionHistoryAllTXIDVersions(ctx context.Context, chain railchain.Chain, startingBlock *uint64) ([]TransactionHistoryEntry, error) {
	return wallet.TransactionHistoryForTXIDVersions(ctx, ActiveTXIDVersions(chain), startingBlock)
}

// TransactionHistoryForTXIDVersions 返回显式 TXID version 列表对应的排序交易历史。
func (wallet *Wallet) TransactionHistoryForTXIDVersions(ctx context.Context, txidVersions []string, startingBlock *uint64) ([]TransactionHistoryEntry, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	history := []TransactionHistoryEntry{}
	for _, txidVersion := range txidVersions {
		versionHistory, err := wallet.TransactionHistory(ctx, txidVersion, startingBlock)
		if err != nil {
			return nil, err
		}
		history = append(history, versionHistory...)
	}
	sortTransactionHistory(history)
	return history, nil
}
