package transaction

import (
	"fmt"
	"math/big"
	"sort"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

var validNullifierCounts = map[int]bool{
	1:  true,
	2:  true,
	3:  true,
	4:  true,
	5:  true,
	6:  true,
	7:  true,
	8:  true,
	9:  true,
	10: true,
}

type SolutionTXO struct {
	ID       string
	TXID     string
	Tree     int
	Position uint64
	Value    *big.Int
}

type TreeBalance struct {
	Balance *big.Int
	UTXOs   []SolutionTXO
}

type SolutionOutput struct {
	ID        string
	Value     *big.Int
	TokenData railcrypto.TokenData
}

type SpendingSolutionGroup struct {
	SpendingTree  int
	UTXOs         []SolutionTXO
	TokenOutputs  []SolutionOutput
	UnshieldValue *big.Int
	TokenData     railcrypto.TokenData
}

type SimpleUTXOGroup struct {
	UTXOs        []SolutionTXO
	SpendingTree int
	Amount       *big.Int
}

func CalculateTotalSpend(utxos []SolutionTXO) *big.Int {
	total := big.NewInt(0)
	for _, utxo := range utxos {
		if utxo.Value != nil {
			total.Add(total, utxo.Value)
		}
	}
	return total
}

func FindExactSolutionsOverTargetValue(treeBalance TreeBalance, totalRequired *big.Int) []SolutionTXO {
	if treeBalance.Balance == nil || totalRequired == nil || treeBalance.Balance.Cmp(totalRequired) < 0 {
		return []SolutionTXO{}
	}
	filtered := filterZeroUTXOs(treeBalance.UTXOs)
	for _, utxo := range filtered {
		if utxo.Value.Cmp(totalRequired) == 0 {
			return []SolutionTXO{cloneSolutionTXO(utxo)}
		}
	}
	sortUTXOsByAscendingValue(filtered)
	var selected []SolutionTXO
	for len(filtered) > len(selected) && CalculateTotalSpend(selected).Cmp(totalRequired) < 0 {
		selected = append(selected, cloneSolutionTXO(filtered[len(selected)]))
	}
	if CalculateTotalSpend(selected).Cmp(totalRequired) < 0 {
		return nil
	}
	if !validNullifierCounts[len(selected)] {
		return nil
	}
	return selected
}

func CreateSimpleSatisfyingUTXOGroup(treeSortedBalances []TreeBalance, amountRequired *big.Int) (SimpleUTXOGroup, error) {
	var selected []SolutionTXO
	spendingTree := -1
	for tree, treeBalance := range treeSortedBalances {
		solutions := FindExactSolutionsOverTargetValue(treeBalance, amountRequired)
		if solutions == nil {
			continue
		}
		spendingTree = tree
		selected = solutions
	}
	if spendingTree < 0 {
		return SimpleUTXOGroup{}, fmt.Errorf("no spending solutions found")
	}
	return SimpleUTXOGroup{
		UTXOs:        cloneSolutionTXOs(selected),
		SpendingTree: spendingTree,
		Amount:       CalculateTotalSpend(selected),
	}, nil
}

func CreateSpendingSolutionsForValue(
	treeSortedBalances []TreeBalance,
	remainingOutputs []SolutionOutput,
	excludedUTXOIDPositions []string,
	isUnshield bool,
) ([]SpendingSolutionGroup, []SolutionOutput, []string, error) {
	if len(remainingOutputs) == 0 {
		return nil, nil, excludedUTXOIDPositions, nil
	}
	remaining := cloneSolutionOutputs(remainingOutputs)
	excluded := append([]string(nil), excludedUTXOIDPositions...)
	primaryOutput := remaining[0]
	var secondaryOutput *SolutionOutput
	if len(remaining) > 1 {
		cloned := cloneSolutionOutput(remaining[1])
		secondaryOutput = &cloned
	}
	if primaryOutput.Value == nil {
		return nil, nil, nil, fmt.Errorf("primary output value is required")
	}
	if primaryOutput.Value.Sign() == 0 {
		replaceOrRemoveRemainingOutput(&remaining, big.NewInt(0))
		nullUTXO := SolutionTXO{ID: "null", TXID: railcrypto.Prefix0x("00"), Tree: 0, Position: 100000, Value: big.NewInt(0)}
		group := createSpendingSolutionGroup(primaryOutput, nullUTXO.Tree, big.NewInt(0), []SolutionTXO{nullUTXO}, isUnshield)
		return []SpendingSolutionGroup{group}, remaining, excluded, nil
	}

	amountToFill := cloneBigInt(primaryOutput.Value)
	var groups []SpendingSolutionGroup
	for tree, treeBalance := range treeSortedBalances {
		for amountToFill.Sign() > 0 {
			utxos := findNextSolutionBatch(treeBalance, amountToFill, excluded)
			if utxos == nil {
				break
			}
			for _, utxo := range utxos {
				excluded = append(excluded, utxoIDPosition(utxo))
			}
			totalSpend := CalculateTotalSpend(utxos)
			solutionValue := minBigInt(totalSpend, amountToFill)
			groups = append(groups, createSpendingSolutionGroup(primaryOutput, tree, solutionValue, utxos, isUnshield))
			amountToFill.Sub(amountToFill, totalSpend)
			replaceOrRemoveRemainingOutput(&remaining, amountToFill)
			if amountToFill.Sign() <= 0 {
				change := new(big.Int).Neg(amountToFill)
				if change.Sign() > 0 && secondaryOutput != nil && !isUnshield {
					secondaryNoteValue := minBigInt(secondaryOutput.Value, change)
					finalAmountToFill := new(big.Int).Sub(secondaryOutput.Value, secondaryNoteValue)
					groups[len(groups)-1].TokenOutputs = append(groups[len(groups)-1].TokenOutputs, SolutionOutput{
						ID:        secondaryOutput.ID,
						Value:     secondaryNoteValue,
						TokenData: secondaryOutput.TokenData,
					})
					replaceOrRemoveRemainingOutput(&remaining, finalAmountToFill)
				}
			}
		}
	}
	if amountToFill.Sign() > 0 {
		return nil, nil, nil, fmt.Errorf("balance too low: requires additional UTXOs to satisfy spending solution")
	}
	return groups, remaining, excluded, nil
}

func ChangeValue(group SpendingSolutionGroup) (*big.Int, error) {
	totalIn := CalculateTotalSpend(group.UTXOs)
	totalOut := cloneBigInt(defaultBigInt(group.UnshieldValue))
	for _, output := range group.TokenOutputs {
		if output.Value != nil {
			totalOut.Add(totalOut, output.Value)
		}
	}
	change := new(big.Int).Sub(totalIn, totalOut)
	if change.Sign() < 0 {
		return nil, fmt.Errorf("negative change value - transaction not possible")
	}
	return change, nil
}

func CreateChangeOutput(walletMasterPublicKey *big.Int, walletViewingPublicKey []byte, group SpendingSolutionGroup, random string, walletSource string) (RequestTransactOutput, *big.Int, *big.Int, error) {
	change, err := ChangeValue(group)
	if err != nil {
		return RequestTransactOutput{}, nil, nil, err
	}
	if change.Sign() == 0 {
		return RequestTransactOutput{}, nil, nil, nil
	}
	notePublicKey, err := railcrypto.NotePublicKey(walletMasterPublicKey, random)
	if err != nil {
		return RequestTransactOutput{}, nil, nil, err
	}
	hash, err := railcrypto.NoteHashFromTokenData(notePublicKey, group.TokenData, change)
	if err != nil {
		return RequestTransactOutput{}, nil, nil, err
	}
	return RequestTransactOutput{
		ReceiverMasterPublicKey:  walletMasterPublicKey,
		ReceiverViewingPublicKey: append([]byte(nil), walletViewingPublicKey...),
		Random:                   random,
		Value:                    change,
		TokenData:                group.TokenData,
		SenderRandom:             railcrypto.MemoSenderRandomNull,
		OutputType:               railcrypto.OutputTypeChange,
		WalletSource:             walletSource,
	}, notePublicKey, hash, nil
}

func createSpendingSolutionGroup(output SolutionOutput, tree int, solutionValue *big.Int, utxos []SolutionTXO, isUnshield bool) SpendingSolutionGroup {
	if isUnshield {
		return SpendingSolutionGroup{
			SpendingTree:  tree,
			UTXOs:         cloneSolutionTXOs(utxos),
			TokenOutputs:  nil,
			UnshieldValue: cloneBigInt(solutionValue),
			TokenData:     output.TokenData,
		}
	}
	return SpendingSolutionGroup{
		SpendingTree: tree,
		UTXOs:        cloneSolutionTXOs(utxos),
		TokenOutputs: []SolutionOutput{{
			ID:        output.ID,
			Value:     cloneBigInt(solutionValue),
			TokenData: output.TokenData,
		}},
		UnshieldValue: big.NewInt(0),
		TokenData:     output.TokenData,
	}
}

func findNextSolutionBatch(treeBalance TreeBalance, totalRequired *big.Int, excludedUTXOIDPositions []string) []SolutionTXO {
	filtered := make([]SolutionTXO, 0, len(treeBalance.UTXOs))
	excluded := map[string]bool{}
	for _, id := range excludedUTXOIDPositions {
		excluded[id] = true
	}
	for _, utxo := range filterZeroUTXOs(treeBalance.UTXOs) {
		if !excluded[utxoIDPosition(utxo)] {
			filtered = append(filtered, cloneSolutionTXO(utxo))
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	for _, utxo := range filtered {
		if utxo.Value.Cmp(totalRequired) == 0 {
			return []SolutionTXO{cloneSolutionTXO(utxo)}
		}
	}
	sortUTXOsByAscendingValue(filtered)
	var selected []SolutionTXO
	for shouldAddMoreUTXOsForSolutionBatch(len(selected), len(filtered), CalculateTotalSpend(selected), totalRequired) {
		selected = append(selected, cloneSolutionTXO(filtered[len(selected)]))
	}
	if !validNullifierCounts[len(selected)] {
		return nil
	}
	return selected
}

func shouldAddMoreUTXOsForSolutionBatch(currentNullifierCount int, totalNullifierCount int, currentSpend *big.Int, totalRequired *big.Int) bool {
	if currentSpend.Cmp(totalRequired) >= 0 {
		return false
	}
	nullifierTarget := nextNullifierTarget(currentNullifierCount)
	if nullifierTarget == 0 {
		return false
	}
	return nullifierTarget <= totalNullifierCount
}

func nextNullifierTarget(utxoCount int) int {
	for i := utxoCount + 1; i <= 10; i++ {
		if validNullifierCounts[i] {
			return i
		}
	}
	return 0
}

func replaceOrRemoveRemainingOutput(remainingOutputs *[]SolutionOutput, amountToFill *big.Int) {
	if len(*remainingOutputs) == 0 {
		return
	}
	deleted := (*remainingOutputs)[0]
	*remainingOutputs = (*remainingOutputs)[1:]
	if amountToFill.Sign() > 0 {
		deleted.Value = cloneBigInt(amountToFill)
		*remainingOutputs = append([]SolutionOutput{deleted}, (*remainingOutputs)...)
	}
}

func filterZeroUTXOs(utxos []SolutionTXO) []SolutionTXO {
	out := make([]SolutionTXO, 0, len(utxos))
	for _, utxo := range utxos {
		if utxo.Value != nil && utxo.Value.Sign() != 0 {
			out = append(out, cloneSolutionTXO(utxo))
		}
	}
	return out
}

func sortUTXOsByAscendingValue(utxos []SolutionTXO) {
	sort.SliceStable(utxos, func(i, j int) bool {
		return utxos[i].Value.Cmp(utxos[j].Value) < 0
	})
}

func utxoIDPosition(utxo SolutionTXO) string {
	return fmt.Sprintf("%s-%d", utxo.TXID, utxo.Position)
}

func minBigInt(a *big.Int, b *big.Int) *big.Int {
	if a.Cmp(b) < 0 {
		return cloneBigInt(a)
	}
	return cloneBigInt(b)
}

func cloneSolutionTXOs(utxos []SolutionTXO) []SolutionTXO {
	out := make([]SolutionTXO, len(utxos))
	for i, utxo := range utxos {
		out[i] = cloneSolutionTXO(utxo)
	}
	return out
}

func cloneSolutionTXO(utxo SolutionTXO) SolutionTXO {
	utxo.Value = cloneBigInt(utxo.Value)
	return utxo
}

func cloneSolutionOutputs(outputs []SolutionOutput) []SolutionOutput {
	out := make([]SolutionOutput, len(outputs))
	for i, output := range outputs {
		out[i] = cloneSolutionOutput(output)
	}
	return out
}

func cloneSolutionOutput(output SolutionOutput) SolutionOutput {
	output.Value = cloneBigInt(output.Value)
	return output
}
