package poi

import (
	"context"
	"fmt"
	"math/big"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

const (
	ListTypeActive = "Active"
	ListTypeGather = "Gather"

	TXOPOIListStatusValid          = "Valid"
	TXOPOIListStatusShieldBlocked  = "ShieldBlocked"
	TXOPOIListStatusProofSubmitted = "ProofSubmitted"
	TXOPOIListStatusMissing        = "Missing"

	BlindedCommitmentTypeShield   = "Shield"
	BlindedCommitmentTypeTransact = "Transact"
	BlindedCommitmentTypeUnshield = "Unshield"

	WalletBalanceBucketSpent              = "Spent"
	WalletBalanceBucketShieldPending      = "ShieldPending"
	WalletBalanceBucketMissingInternalPOI = "MissingInternalPOI"
	WalletBalanceBucketMissingExternalPOI = "MissingExternalPOI"
	WalletBalanceBucketSpendable          = "Spendable"
	WalletBalanceBucketShieldBlocked      = "ShieldBlocked"
	WalletBalanceBucketProofSubmitted     = "ProofSubmitted"

	CommitmentTypeShield             = "ShieldCommitment"
	CommitmentTypeLegacyGenerated    = "LegacyGeneratedCommitment"
	CommitmentTypeTransactV2         = "TransactCommitmentV2"
	CommitmentTypeTransactV3         = "TransactCommitmentV3"
	CommitmentTypeLegacyEncrypted    = "LegacyEncryptedCommitment"
	maxBlindedCommitmentPOIRetrieval = 1000
)

type List struct {
	Key         string `json:"key"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type POIsPerList map[string]string

type BlindedCommitmentData struct {
	BlindedCommitment string `json:"blindedCommitment"`
	Type              string `json:"type"`
}

type LegacyTransactProofData struct {
	TXIDIndex         string `json:"txidIndex"`
	NPK               string `json:"npk"`
	Value             string `json:"value"`
	TokenHash         string `json:"tokenHash"`
	BlindedCommitment string `json:"blindedCommitment"`
}

type TXO struct {
	SpendTXID                   string
	POIsPerList                 POIsPerList
	CommitmentType              string
	OutputType                  *int
	Value                       *big.Int
	BlindedCommitment           string
	BlockNumber                 uint64
	TransactCreationRailgunTxid string
}

type SentCommitment struct {
	POIsPerList       POIsPerList
	Value             *big.Int
	BlindedCommitment string
	RailgunTxid       string
}

type UnshieldPOIEvent struct {
	POIsPerList POIsPerList
	RailgunTxid string
}

type NodeInterface interface {
	IsActive(chain railchain.Chain) bool
	IsRequired(ctx context.Context, chain railchain.Chain) (bool, error)
	GetPOIsPerList(ctx context.Context, request GetPOIsPerListRequest) (map[string]POIsPerList, error)
	GetPOIMerkleProofs(ctx context.Context, request GetPOIMerkleProofsRequest) ([]merkletree.MerkleProof, error)
	ValidatePOIMerkleRoots(ctx context.Context, request ValidatePOIMerkleRootsRequest) (bool, error)
	SubmitPOI(ctx context.Context, request SubmitPOIRequest) error
	SubmitLegacyTransactProofs(ctx context.Context, request SubmitLegacyTransactProofsRequest) error
}

type GetPOIsPerListRequest struct {
	TXIDVersion            string                  `json:"txidVersion"`
	Chain                  railchain.Chain         `json:"chain"`
	ListKeys               []string                `json:"listKeys"`
	BlindedCommitmentDatas []BlindedCommitmentData `json:"blindedCommitmentDatas"`
}

type GetPOIMerkleProofsRequest struct {
	TXIDVersion        string          `json:"txidVersion"`
	Chain              railchain.Chain `json:"chain"`
	ListKey            string          `json:"listKey"`
	BlindedCommitments []string        `json:"blindedCommitments"`
}

type ValidatePOIMerkleRootsRequest struct {
	TXIDVersion    string          `json:"txidVersion"`
	Chain          railchain.Chain `json:"chain"`
	ListKey        string          `json:"listKey"`
	POIMerkleRoots []string        `json:"poiMerkleroots"`
}

type SubmitPOIRequest struct {
	TXIDVersion              string          `json:"txidVersion"`
	Chain                    railchain.Chain `json:"chain"`
	ListKey                  string          `json:"listKey"`
	SnarkProof               railproof.Proof `json:"snarkProof"`
	POIMerkleRoots           []string        `json:"poiMerkleroots"`
	TxidMerkleRoot           string          `json:"txidMerkleroot"`
	TxidMerkleRootIndex      uint64          `json:"txidMerklerootIndex"`
	BlindedCommitmentsOut    []string        `json:"blindedCommitmentsOut"`
	RailgunTxidIfHasUnshield string          `json:"railgunTxidIfHasUnshield"`
}

type SubmitLegacyTransactProofsRequest struct {
	TXIDVersion              string                    `json:"txidVersion"`
	Chain                    railchain.Chain           `json:"chain"`
	ListKeys                 []string                  `json:"listKeys"`
	LegacyTransactProofDatas []LegacyTransactProofData `json:"legacyTransactProofDatas"`
}

type Manager struct {
	lists        []List
	node         NodeInterface
	launchBlocks map[railchain.Chain]uint64
}

func NewManager(lists []List, node NodeInterface) *Manager {
	return &Manager{
		lists:        cloneLists(lists),
		node:         node,
		launchBlocks: map[railchain.Chain]uint64{},
	}
}

func (manager *Manager) GetAllListKeys() []string {
	if manager == nil {
		return nil
	}
	keys := make([]string, len(manager.lists))
	for i, list := range manager.lists {
		keys[i] = list.Key
	}
	return keys
}

func (manager *Manager) GetActiveListKeys() []string {
	if manager == nil {
		return nil
	}
	keys := []string{}
	for _, list := range manager.lists {
		if list.Type == ListTypeActive {
			keys = append(keys, list.Key)
		}
	}
	return keys
}

func (manager *Manager) SetLaunchBlock(chain railchain.Chain, blockNumber uint64) {
	if manager == nil {
		return
	}
	if manager.launchBlocks == nil {
		manager.launchBlocks = map[railchain.Chain]uint64{}
	}
	manager.launchBlocks[chain] = blockNumber
}

func (manager *Manager) LaunchBlock(chain railchain.Chain) (uint64, bool) {
	if manager == nil || manager.launchBlocks == nil {
		return 0, false
	}
	blockNumber, ok := manager.launchBlocks[chain]
	return blockNumber, ok
}

func (manager *Manager) IsLegacyTXO(chain railchain.Chain, txo TXO) bool {
	launchBlock, ok := manager.LaunchBlock(chain)
	return !ok || txo.BlockNumber < launchBlock
}

func (manager *Manager) ShouldSubmitLegacyTransactEventsTXO(chain railchain.Chain, txo TXO) bool {
	if manager == nil {
		return false
	}
	if txo.TransactCreationRailgunTxid == "" || txo.BlindedCommitment == "" {
		return false
	}
	if !manager.IsLegacyTXO(chain, txo) {
		return false
	}
	if txo.POIsPerList == nil {
		return false
	}
	if !isTransactCommitmentType(txo.CommitmentType) {
		return false
	}
	return !hasValidPOIsAllLists(txo.POIsPerList, manager.GetAllListKeys())
}

func (manager *Manager) IsActiveForChain(chain railchain.Chain) bool {
	if manager == nil || manager.node == nil {
		return false
	}
	return manager.node.IsActive(chain)
}

func (manager *Manager) IsRequiredForChain(ctx context.Context, chain railchain.Chain) (bool, error) {
	if manager == nil || manager.node == nil {
		return false, fmt.Errorf("POI node interface not initialized")
	}
	return manager.node.IsRequired(ctx, chain)
}

func (manager *Manager) GetSpendableBalanceBuckets(ctx context.Context, chain railchain.Chain) ([]string, error) {
	required, err := manager.IsRequiredForChain(ctx, chain)
	if err != nil {
		return nil, err
	}
	if required {
		return []string{WalletBalanceBucketSpendable}, nil
	}
	return []string{
		WalletBalanceBucketShieldPending,
		WalletBalanceBucketMissingInternalPOI,
		WalletBalanceBucketMissingExternalPOI,
		WalletBalanceBucketSpendable,
		WalletBalanceBucketShieldBlocked,
		WalletBalanceBucketProofSubmitted,
	}, nil
}

func (manager *Manager) GetBalanceBucket(txo TXO) string {
	if txo.SpendTXID != "" {
		return WalletBalanceBucketSpent
	}

	activeListKeys := manager.GetActiveListKeys()
	isChange := txo.OutputType != nil && *txo.OutputType == railcrypto.OutputTypeChange
	if !hasAllKeys(txo.POIsPerList, activeListKeys) {
		if isShieldCommitmentType(txo.CommitmentType) {
			return WalletBalanceBucketShieldPending
		}
		if isChange {
			return WalletBalanceBucketMissingInternalPOI
		}
		return WalletBalanceBucketMissingExternalPOI
	}

	if manager.HasValidPOIsActiveLists(txo.POIsPerList) {
		return WalletBalanceBucketSpendable
	}
	for _, listKey := range activeListKeys {
		if txo.POIsPerList[listKey] == TXOPOIListStatusShieldBlocked {
			return WalletBalanceBucketShieldBlocked
		}
	}
	if isShieldCommitmentType(txo.CommitmentType) {
		return WalletBalanceBucketShieldPending
	}
	for _, listKey := range activeListKeys {
		if txo.POIsPerList[listKey] == TXOPOIListStatusProofSubmitted {
			return WalletBalanceBucketProofSubmitted
		}
	}
	if isChange {
		return WalletBalanceBucketMissingInternalPOI
	}
	return WalletBalanceBucketMissingExternalPOI
}

func (manager *Manager) HasValidPOIsActiveLists(pois POIsPerList) bool {
	return validatePOIStatusForLists(pois, manager.GetActiveListKeys(), []string{TXOPOIListStatusValid})
}

func (manager *Manager) GetListKeysCanGenerateSpentPOIs(spentTXOs []TXO, sentCommitments []SentCommitment, unshieldEvents []UnshieldPOIEvent, isLegacyPOIProof bool) []string {
	if len(sentCommitments) == 0 && len(unshieldEvents) == 0 {
		return nil
	}

	listKeys := manager.GetAllListKeys()
	if !isLegacyPOIProof {
		inputPOIs := make([]POIsPerList, 0, len(spentTXOs))
		for _, txo := range spentTXOs {
			if txo.POIsPerList != nil {
				inputPOIs = append(inputPOIs, txo.POIsPerList)
			}
		}
		listKeys = manager.getAllListKeysWithValidInputPOIs(inputPOIs)
	}

	validStatuses := map[string]bool{
		TXOPOIListStatusValid:          true,
		TXOPOIListStatusProofSubmitted: true,
	}
	out := []string{}
	for _, listKey := range listKeys {
		allSentCommitmentsValid := true
		for _, sentCommitment := range sentCommitments {
			if bigIntIsZero(sentCommitment.Value) {
				continue
			}
			if !validStatuses[sentCommitment.POIsPerList[listKey]] {
				allSentCommitmentsValid = false
				break
			}
		}
		allUnshieldEventsValid := true
		for _, unshieldEvent := range unshieldEvents {
			if !validStatuses[unshieldEvent.POIsPerList[listKey]] {
				allUnshieldEventsValid = false
				break
			}
		}
		if !(allSentCommitmentsValid && allUnshieldEventsValid) {
			out = append(out, listKey)
		}
	}
	return out
}

func (manager *Manager) GetListKeysCanSubmitLegacyTransactEvents(txos []TXO) []string {
	out := []string{}
	for _, listKey := range manager.GetAllListKeys() {
		allValid := true
		for _, txo := range txos {
			if txo.POIsPerList[listKey] != TXOPOIListStatusValid {
				allValid = false
				break
			}
		}
		if !allValid {
			out = append(out, listKey)
		}
	}
	return out
}

func (manager *Manager) ShouldRetrieveTXOPOIs(txo TXO) bool {
	if txo.BlindedCommitment == "" {
		return false
	}
	return !hasValidPOIsAllLists(txo.POIsPerList, manager.GetAllListKeys())
}

func (manager *Manager) ShouldRetrieveSentCommitmentPOIs(sentCommitment SentCommitment) bool {
	if sentCommitment.BlindedCommitment == "" || bigIntIsZero(sentCommitment.Value) {
		return false
	}
	return !hasValidPOIsAllLists(sentCommitment.POIsPerList, manager.GetAllListKeys())
}

func (manager *Manager) ShouldRetrieveUnshieldEventPOIs(unshieldEvent UnshieldPOIEvent) bool {
	if unshieldEvent.RailgunTxid == "" {
		return false
	}
	return !hasValidPOIsAllLists(unshieldEvent.POIsPerList, manager.GetAllListKeys())
}

func (manager *Manager) ShouldGenerateSpentPOIsSentCommitment(sentCommitment SentCommitment) bool {
	if sentCommitment.BlindedCommitment == "" || bigIntIsZero(sentCommitment.Value) {
		return false
	}
	return len(manager.findListsForNewPOIs(sentCommitment.POIsPerList)) > 0
}

func (manager *Manager) ShouldGenerateSpentPOIsUnshieldEvent(unshieldEvent UnshieldPOIEvent) bool {
	if unshieldEvent.RailgunTxid == "" {
		return false
	}
	return len(manager.findListsForNewPOIs(unshieldEvent.POIsPerList)) > 0
}

func (manager *Manager) RetrievePOIsForBlindedCommitments(ctx context.Context, txidVersion string, chain railchain.Chain, blindedCommitmentDatas []BlindedCommitmentData) (map[string]POIsPerList, error) {
	if manager == nil || manager.node == nil {
		return nil, fmt.Errorf("POI node interface not initialized")
	}
	if len(blindedCommitmentDatas) > maxBlindedCommitmentPOIRetrieval {
		return nil, fmt.Errorf("Cannot retrieve POIs for more than 1000 blinded commitments at a time")
	}
	return manager.node.GetPOIsPerList(ctx, GetPOIsPerListRequest{
		TXIDVersion:            txidVersion,
		Chain:                  chain,
		ListKeys:               manager.GetAllListKeys(),
		BlindedCommitmentDatas: cloneBlindedCommitmentDatas(blindedCommitmentDatas),
	})
}

func (manager *Manager) GetPOIMerkleProofs(ctx context.Context, txidVersion string, chain railchain.Chain, listKey string, blindedCommitments []string) ([]merkletree.MerkleProof, error) {
	if manager == nil || manager.node == nil {
		return nil, fmt.Errorf("POI node interface not initialized")
	}
	return manager.node.GetPOIMerkleProofs(ctx, GetPOIMerkleProofsRequest{
		TXIDVersion:        txidVersion,
		Chain:              chain,
		ListKey:            listKey,
		BlindedCommitments: append([]string(nil), blindedCommitments...),
	})
}

func (manager *Manager) ValidatePOIMerkleRoots(ctx context.Context, txidVersion string, chain railchain.Chain, listKey string, poiMerkleRoots []string) (bool, error) {
	if manager == nil || manager.node == nil {
		return false, fmt.Errorf("POI node interface not initialized")
	}
	return manager.node.ValidatePOIMerkleRoots(ctx, ValidatePOIMerkleRootsRequest{
		TXIDVersion:    txidVersion,
		Chain:          chain,
		ListKey:        listKey,
		POIMerkleRoots: append([]string(nil), poiMerkleRoots...),
	})
}

func (manager *Manager) SubmitPOI(ctx context.Context, request SubmitPOIRequest) error {
	if manager == nil || manager.node == nil {
		return fmt.Errorf("POI node interface not initialized")
	}
	request.POIMerkleRoots = append([]string(nil), request.POIMerkleRoots...)
	request.BlindedCommitmentsOut = append([]string(nil), request.BlindedCommitmentsOut...)
	return manager.node.SubmitPOI(ctx, request)
}

func (manager *Manager) SubmitLegacyTransactProofs(ctx context.Context, request SubmitLegacyTransactProofsRequest) error {
	if manager == nil || manager.node == nil {
		return fmt.Errorf("POI node interface not initialized")
	}
	request.ListKeys = append([]string(nil), request.ListKeys...)
	request.LegacyTransactProofDatas = append([]LegacyTransactProofData(nil), request.LegacyTransactProofDatas...)
	return manager.node.SubmitLegacyTransactProofs(ctx, request)
}

func (manager *Manager) getAllListKeysWithValidInputPOIs(inputPOIsPerList []POIsPerList) []string {
	out := []string{}
	for _, listKey := range manager.GetAllListKeys() {
		allValid := true
		for _, pois := range inputPOIsPerList {
			if pois[listKey] != TXOPOIListStatusValid {
				allValid = false
				break
			}
		}
		if allValid {
			out = append(out, listKey)
		}
	}
	return out
}

func (manager *Manager) findListsForNewPOIs(pois POIsPerList) []string {
	listKeys := manager.GetAllListKeys()
	if pois == nil {
		return listKeys
	}
	out := []string{}
	for _, listKey := range listKeys {
		status := pois[listKey]
		if status != TXOPOIListStatusProofSubmitted && status != TXOPOIListStatusValid {
			out = append(out, listKey)
		}
	}
	return out
}

func validatePOIStatusForLists(pois POIsPerList, listKeys []string, statuses []string) bool {
	if !hasAllKeys(pois, listKeys) {
		return false
	}
	allowed := map[string]bool{}
	for _, status := range statuses {
		allowed[status] = true
	}
	for _, listKey := range listKeys {
		if !allowed[pois[listKey]] {
			return false
		}
	}
	return true
}

func hasValidPOIsAllLists(pois POIsPerList, listKeys []string) bool {
	return validatePOIStatusForLists(pois, listKeys, []string{TXOPOIListStatusValid})
}

func hasAllKeys(pois POIsPerList, keys []string) bool {
	if pois == nil {
		return len(keys) == 0
	}
	for _, key := range keys {
		if _, ok := pois[key]; !ok {
			return false
		}
	}
	return true
}

func isShieldCommitmentType(commitmentType string) bool {
	return commitmentType == CommitmentTypeShield || commitmentType == CommitmentTypeLegacyGenerated
}

func isTransactCommitmentType(commitmentType string) bool {
	return commitmentType == CommitmentTypeTransactV2 ||
		commitmentType == CommitmentTypeTransactV3 ||
		commitmentType == CommitmentTypeLegacyEncrypted
}

func bigIntIsZero(value *big.Int) bool {
	return value == nil || value.Sign() == 0
}

func cloneLists(lists []List) []List {
	return append([]List(nil), lists...)
}

func cloneBlindedCommitmentDatas(values []BlindedCommitmentData) []BlindedCommitmentData {
	return append([]BlindedCommitmentData(nil), values...)
}
