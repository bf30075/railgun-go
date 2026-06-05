package wallet

import (
	"context"
	"fmt"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
)

func (wallet *Wallet) WalletDetailsMap(ctx context.Context, chain railchain.Chain) (WalletDetailsMap, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	if wallet.Details == nil {
		return WalletDetailsMap{}, nil
	}
	return wallet.Details.LoadWalletDetailsMap(ctx, chain)
}

func (wallet *Wallet) WalletDetails(ctx context.Context, txidVersion string, chain railchain.Chain) (WalletDetails, error) {
	if err := wallet.validate(); err != nil {
		return WalletDetails{}, err
	}
	if txidVersion == "" {
		return WalletDetails{}, fmt.Errorf("txid version is required")
	}
	detailsMap, err := wallet.WalletDetailsMap(ctx, chain)
	if err != nil {
		return WalletDetails{}, err
	}
	details, ok := detailsMap[txidVersion]
	if !ok {
		return defaultWalletDetails(), nil
	}
	return cloneWalletDetails(details), nil
}

func (wallet *Wallet) SaveWalletDetails(ctx context.Context, txidVersion string, chain railchain.Chain, details WalletDetails) error {
	if err := wallet.validate(); err != nil {
		return err
	}
	if wallet.Details == nil {
		return fmt.Errorf("wallet details store is required")
	}
	if txidVersion == "" {
		return fmt.Errorf("txid version is required")
	}
	detailsMap, err := wallet.Details.LoadWalletDetailsMap(ctx, chain)
	if err != nil {
		return err
	}
	detailsMap[txidVersion] = cloneWalletDetails(details)
	return wallet.Details.SaveWalletDetailsMap(ctx, chain, detailsMap)
}

func (wallet *Wallet) UpdateTreeScannedHeight(ctx context.Context, txidVersion string, chain railchain.Chain, tree uint64, height uint64) error {
	details, err := wallet.WalletDetails(ctx, txidVersion, chain)
	if err != nil {
		return err
	}
	for len(details.TreeScannedHeights) <= int(tree) {
		details.TreeScannedHeights = append(details.TreeScannedHeights, 0)
	}
	details.TreeScannedHeights[tree] = height
	return wallet.SaveWalletDetails(ctx, txidVersion, chain, details)
}

func (wallet *Wallet) SetWalletCreationDetails(ctx context.Context, txidVersion string, chain railchain.Chain, creationTree *uint64, creationTreeHeight *uint64) error {
	details, err := wallet.WalletDetails(ctx, txidVersion, chain)
	if err != nil {
		return err
	}
	details.CreationTree = cloneUint64Ptr(creationTree)
	details.CreationTreeHeight = cloneUint64Ptr(creationTreeHeight)
	return wallet.SaveWalletDetails(ctx, txidVersion, chain, details)
}
