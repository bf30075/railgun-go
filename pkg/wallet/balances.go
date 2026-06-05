package wallet

import (
	"context"
	"fmt"
	"math/big"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
)

type TokenBalancesByBucket map[string]TokenBalances

type TreeBalance struct {
	Balance   *big.Int
	TokenData railcrypto.TokenData
	UTXOs     []StoredTXO
}

type TotalBalancesByTreeNumber map[string][]TreeBalance

func (wallet *Wallet) BalancesByBucket(ctx context.Context, txidVersion string) (TokenBalancesByBucket, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	if txidVersion == "" {
		return nil, fmt.Errorf("txid version is required")
	}
	txos, err := wallet.State.ListTXOs(ctx)
	if err != nil {
		return nil, err
	}
	txos = txosForTXIDVersion(txos, txidVersion)
	out := TokenBalancesByBucket{}
	for _, bucket := range walletBalanceBuckets() {
		balances, err := tokenBalancesFromTXOs(txos, wallet.POIManager, []string{bucket})
		if err != nil {
			return nil, err
		}
		out[bucket] = balances
	}
	return out, nil
}

func (wallet *Wallet) BalanceERC20(ctx context.Context, txidVersion string, tokenAddress string, includedBuckets []string) (*big.Int, bool, error) {
	tokenData, err := railcrypto.TokenDataERC20(tokenAddress)
	if err != nil {
		return nil, false, err
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		return nil, false, err
	}
	balances, err := wallet.BalancesForTXIDVersion(ctx, txidVersion, includedBuckets)
	if err != nil {
		return nil, false, err
	}
	balance, ok := balances[tokenHash]
	if !ok {
		return nil, false, nil
	}
	return cloneBigInt(balance.Balance), true, nil
}

func (wallet *Wallet) BalancesForUnshieldToOrigin(ctx context.Context, txidVersion string, originShieldTxid string) (TokenBalances, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	if txidVersion == "" {
		return nil, fmt.Errorf("txid version is required")
	}
	origin, err := railcrypto.FormatHexToByteLength(originShieldTxid, 32, true)
	if err != nil {
		return nil, err
	}
	txos, err := wallet.State.ListTXOs(ctx)
	if err != nil {
		return nil, err
	}
	candidates := []StoredTXO{}
	for _, txo := range txosForTXIDVersion(txos, txidVersion) {
		if txo.SpendTXID != "" || txo.TXID == "" || !isShieldCommitmentTypeForBalance(txo.CommitmentType) {
			continue
		}
		txoTxid, err := railcrypto.FormatHexToByteLength(txo.TXID, 32, true)
		if err != nil {
			return nil, err
		}
		if txoTxid == origin {
			candidates = append(candidates, txo)
		}
	}
	return tokenBalancesFromTXOs(candidates, wallet.POIManager, nil)
}

func (wallet *Wallet) TotalBalancesByTreeNumber(ctx context.Context, txidVersion string, includedBuckets []string) (TotalBalancesByTreeNumber, error) {
	balances, err := wallet.BalancesForTXIDVersion(ctx, txidVersion, includedBuckets)
	if err != nil {
		return nil, err
	}
	return totalBalancesByTreeNumberFromBalances(balances), nil
}

func (wallet *Wallet) TotalBalancesByTreeNumberForUnshieldToOrigin(ctx context.Context, txidVersion string, originShieldTxid string) (TotalBalancesByTreeNumber, error) {
	balances, err := wallet.BalancesForUnshieldToOrigin(ctx, txidVersion, originShieldTxid)
	if err != nil {
		return nil, err
	}
	return totalBalancesByTreeNumberFromBalances(balances), nil
}

func (wallet *Wallet) BalancesByTreeForToken(ctx context.Context, txidVersion string, tokenHash string, includedBuckets []string) ([]TreeBalance, error) {
	totalBalances, err := wallet.TotalBalancesByTreeNumber(ctx, txidVersion, includedBuckets)
	if err != nil {
		return nil, err
	}
	return totalBalances[tokenHash], nil
}

func (wallet *Wallet) BalancesByTreeForTokenForUnshieldToOrigin(ctx context.Context, txidVersion string, tokenHash string, originShieldTxid string) ([]TreeBalance, error) {
	totalBalances, err := wallet.TotalBalancesByTreeNumberForUnshieldToOrigin(ctx, txidVersion, originShieldTxid)
	if err != nil {
		return nil, err
	}
	return totalBalances[tokenHash], nil
}

func totalBalancesByTreeNumberFromBalances(balances TokenBalances) TotalBalancesByTreeNumber {
	out := TotalBalancesByTreeNumber{}
	for tokenHash, balance := range balances {
		treeBalances := []TreeBalance{}
		for _, txo := range balance.UTXOs {
			for len(treeBalances) <= int(txo.Tree) {
				treeBalances = append(treeBalances, TreeBalance{})
			}
			treeBalance := treeBalances[txo.Tree]
			if treeBalance.Balance == nil {
				treeBalance.Balance = big.NewInt(0)
				treeBalance.TokenData = txo.TokenData
			}
			treeBalance.Balance.Add(treeBalance.Balance, txo.Value)
			treeBalance.UTXOs = append(treeBalance.UTXOs, cloneStoredTXO(txo))
			treeBalances[txo.Tree] = treeBalance
		}
		out[tokenHash] = treeBalances
	}
	return out
}

func TokenBalanceAcrossAllTrees(treeSortedBalances []TreeBalance) *big.Int {
	total := big.NewInt(0)
	for _, treeBalance := range treeSortedBalances {
		if treeBalance.Balance != nil {
			total.Add(total, treeBalance.Balance)
		}
	}
	return total
}

func walletBalanceBuckets() []string {
	return []string{
		railpoi.WalletBalanceBucketSpent,
		railpoi.WalletBalanceBucketShieldPending,
		railpoi.WalletBalanceBucketMissingInternalPOI,
		railpoi.WalletBalanceBucketMissingExternalPOI,
		railpoi.WalletBalanceBucketSpendable,
		railpoi.WalletBalanceBucketShieldBlocked,
		railpoi.WalletBalanceBucketProofSubmitted,
	}
}

func isShieldCommitmentTypeForBalance(commitmentType string) bool {
	return commitmentType == railpoi.CommitmentTypeShield || commitmentType == railpoi.CommitmentTypeLegacyGenerated
}
