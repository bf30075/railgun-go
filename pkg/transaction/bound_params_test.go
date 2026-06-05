package transaction

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"strconv"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

type exportedFixtures struct {
	BoundParamsFixtures          boundParamsFixtureSet          `json:"boundParamsFixtures"`
	CommitmentCiphertextFixtures commitmentCiphertextFixtureSet `json:"commitmentCiphertextFixtures"`
	SpendingSolutionFixtures     spendingSolutionFixtureSet     `json:"spendingSolutionFixtures"`
	TransactionRequestFixtures   transactionRequestFixtureSet   `json:"transactionRequestFixtures"`
	DummyBatchFixtures           dummyBatchFixtureSet           `json:"dummyBatchFixtures"`
	RelayAdaptFixtures           relayAdaptFixtureSet           `json:"relayAdaptFixtures"`
	TransactionStructFixtures    transactionStructFixtureSet    `json:"transactionStructFixtures"`
	ShieldFixtures               shieldFixtureSet               `json:"shieldFixtures"`
	CalldataFixtures             calldataFixtureSet             `json:"calldataFixtures"`
	TransactNoteFixtures         transactNoteFixtureSet         `json:"transactNoteFixtures"`
}

type boundParamsFixtureSet struct {
	V2 boundParamsV2Fixture `json:"v2"`
	V3 boundParamsV3Fixture `json:"v3"`
}

type transactionStructFixtureSet struct {
	V2 NativeTransactionStructV2 `json:"v2"`
	V3 NativeTransactionStructV3 `json:"v3"`
}

type transactionRequestFixtureSet struct {
	Inputs  transactionRequestInputsFixture `json:"inputs"`
	V2      NativeTransactionRequestV2      `json:"v2"`
	V3      NativeTransactionRequestV3      `json:"v3"`
	DummyV2 NativeTransactionStructV2       `json:"dummyV2"`
	DummyV3 NativeTransactionStructV3       `json:"dummyV3"`
}

type dummyBatchFixtureSet struct {
	Inputs     dummyBatchInputsFixture       `json:"inputs"`
	UnprovedV2 []nativeUnprovedTransactionV2 `json:"unprovedV2"`
	UnprovedV3 []nativeUnprovedTransactionV3 `json:"unprovedV3"`
	V2         []NativeTransactionStructV2   `json:"v2"`
	V3         []NativeTransactionStructV3   `json:"v3"`
}

type spendingSolutionFixtureSet struct {
	Inputs                  spendingSolutionInputsFixture `json:"inputs"`
	Exact                   []nativeSolutionTXO           `json:"exact"`
	SimpleGroup             nativeSimpleUTXOGroup         `json:"simpleGroup"`
	ComplexGroups           []nativeSpendingSolutionGroup `json:"complexGroups"`
	ComplexExcluded         []string                      `json:"complexExcluded"`
	ComplexRemainingOutputs []nativeSolutionOutput        `json:"complexRemainingOutputs"`
	ChangeOutput            nativeChangeOutput            `json:"changeOutput"`
}

type spendingSolutionInputsFixture struct {
	TokenData          railcrypto.TokenData        `json:"tokenData"`
	WalletAddressData  walletAddressFixture        `json:"walletAddressData"`
	SimpleTreeBalance  nativeTreeBalance           `json:"simpleTreeBalance"`
	SimpleRequired     string                      `json:"simpleRequired"`
	ComplexTreeBalance nativeTreeBalance           `json:"complexTreeBalance"`
	ComplexOutputs     []nativeSolutionInputOutput `json:"complexOutputs"`
	ChangeRandom       string                      `json:"changeRandom"`
	WalletSource       string                      `json:"walletSource"`
}

type walletAddressFixture struct {
	MasterPublicKey  string `json:"masterPublicKey"`
	ViewingPublicKey string `json:"viewingPublicKey"`
}

type nativeTreeBalance struct {
	Balance string              `json:"balance"`
	UTXOs   []nativeSolutionTXO `json:"utxos"`
}

type nativeSolutionTXO struct {
	ID       string `json:"id"`
	TXID     string `json:"txid"`
	Tree     string `json:"tree"`
	Position string `json:"position"`
	Value    string `json:"value"`
}

type nativeSimpleUTXOGroup struct {
	SpendingTree string              `json:"spendingTree"`
	Amount       string              `json:"amount"`
	UTXOs        []nativeSolutionTXO `json:"utxos"`
}

type nativeSpendingSolutionGroup struct {
	SpendingTree  string                 `json:"spendingTree"`
	UTXOs         []nativeSolutionTXO    `json:"utxos"`
	TokenOutputs  []nativeSolutionOutput `json:"tokenOutputs"`
	UnshieldValue string                 `json:"unshieldValue"`
	TokenData     railcrypto.TokenData   `json:"tokenData"`
}

type nativeSolutionOutput struct {
	Value string `json:"value"`
}

type nativeSolutionInputOutput struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type nativeChangeOutput struct {
	Random                    string `json:"random"`
	Value                     string `json:"value"`
	TokenHash                 string `json:"tokenHash"`
	NotePublicKey             string `json:"notePublicKey"`
	Hash                      string `json:"hash"`
	OutputType                int    `json:"outputType"`
	WalletSource              string `json:"walletSource"`
	SenderRandom              string `json:"senderRandom"`
	RecipientMasterPublicKey  string `json:"recipientMasterPublicKey"`
	RecipientViewingPublicKey string `json:"recipientViewingPublicKey"`
}

type nativeUnprovedTransactionV2 struct {
	Request   NativeTransactionRequestV2 `json:"request"`
	Signature [3]string                  `json:"signature"`
}

type nativeUnprovedTransactionV3 struct {
	Request   NativeTransactionRequestV3 `json:"request"`
	Signature [3]string                  `json:"signature"`
}

type transactionRequestInputsFixture struct {
	Chain                    Chain                             `json:"chain"`
	SpendingTree             string                            `json:"spendingTree"`
	MerkleRoot               string                            `json:"merkleRoot"`
	MerkleProofElements      []string                          `json:"merkleProofElements"`
	TokenData                railcrypto.TokenData              `json:"tokenData"`
	SpendingPublicKey        [2]string                         `json:"spendingPublicKey"`
	NullifyingKey            string                            `json:"nullifyingKey"`
	SenderMasterPublicKey    string                            `json:"senderMasterPublicKey"`
	SenderViewingPrivateKey  string                            `json:"senderViewingPrivateKey"`
	SenderViewingPublicKey   string                            `json:"senderViewingPublicKey"`
	ReceiverMasterPublicKey  string                            `json:"receiverMasterPublicKey"`
	ReceiverViewingPublicKey string                            `json:"receiverViewingPublicKey"`
	UTXOs                    []transactionRequestUTXOFixture   `json:"utxos"`
	Outputs                  []transactionRequestOutputFixture `json:"outputs"`
	AdaptID                  AdaptID                           `json:"adaptID"`
	MinGasPrice              string                            `json:"minGasPrice"`
	GlobalBoundParams        globalBoundParamsV3JSON           `json:"globalBoundParams"`
	V2NoteCiphertextIV       string                            `json:"v2NoteCiphertextIV"`
	V2AnnotationIV           string                            `json:"v2AnnotationIV"`
	V3NoteCiphertextNonce    string                            `json:"v3NoteCiphertextNonce"`
}

type dummyBatchInputsFixture struct {
	Chain                    Chain                             `json:"chain"`
	OverallBatchMinGasPrice  string                            `json:"overallBatchMinGasPrice"`
	SpendingTree             string                            `json:"spendingTree"`
	MerkleRoot               string                            `json:"merkleRoot"`
	MerkleProofElements      []string                          `json:"merkleProofElements"`
	TokenData                railcrypto.TokenData              `json:"tokenData"`
	SpendingPrivateKey       string                            `json:"spendingPrivateKey"`
	SpendingPublicKey        [2]string                         `json:"spendingPublicKey"`
	NullifyingKey            string                            `json:"nullifyingKey"`
	WalletMasterPublicKey    string                            `json:"walletMasterPublicKey"`
	WalletViewingPrivateKey  string                            `json:"walletViewingPrivateKey"`
	WalletViewingPublicKey   string                            `json:"walletViewingPublicKey"`
	ReceiverMasterPublicKey  string                            `json:"receiverMasterPublicKey"`
	ReceiverViewingPublicKey string                            `json:"receiverViewingPublicKey"`
	UTXOs                    []transactionRequestUTXOFixture   `json:"utxos"`
	Outputs                  []transactionRequestOutputFixture `json:"outputs"`
	AdaptID                  AdaptID                           `json:"adaptID"`
	GlobalBoundParams        globalBoundParamsV3JSON           `json:"globalBoundParams"`
	WalletSource             string                            `json:"walletSource"`
	ChangeRandom             string                            `json:"changeRandom"`
	V2NoteCiphertextIVs      []string                          `json:"v2NoteCiphertextIVs"`
	V2AnnotationIVs          []string                          `json:"v2AnnotationIVs"`
	V3NoteCiphertextNonces   []string                          `json:"v3NoteCiphertextNonces"`
}

type transactionRequestUTXOFixture struct {
	Position   string `json:"position"`
	NoteRandom string `json:"noteRandom"`
	NoteValue  string `json:"noteValue"`
}

type transactionRequestOutputFixture struct {
	Random       string `json:"random"`
	Value        string `json:"value"`
	SenderRandom string `json:"senderRandom"`
	OutputType   int    `json:"outputType"`
	WalletSource string `json:"walletSource"`
	MemoText     string `json:"memoText"`
}

type calldataFixtureSet struct {
	V2Transact        string `json:"v2Transact"`
	V3ExecuteTransact string `json:"v3ExecuteTransact"`
}

type shieldFixtureSet struct {
	ChainID                 string              `json:"chainID"`
	Request                 NativeShieldRequest `json:"request"`
	ShieldNote              shieldNoteFixture   `json:"shieldNote"`
	V2ShieldCalldata        string              `json:"v2ShieldCalldata"`
	V3ExecuteShieldCalldata string              `json:"v3ExecuteShieldCalldata"`
}

type commitmentCiphertextFixtureSet struct {
	Blinding commitmentCiphertextBlindingFixture `json:"blinding"`
	V2       NativeCommitmentCiphertextV2        `json:"v2"`
	V3       NativeCommitmentCiphertextV3        `json:"v3"`
}

type commitmentCiphertextBlindingFixture struct {
	BlindedSenderViewingKey   string `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string `json:"blindedReceiverViewingKey"`
}

type transactNoteFixtureSet struct {
	V2 railcrypto.TransactNoteV2Encryption `json:"v2"`
	V3 railcrypto.TransactNoteV3Encryption `json:"v3"`
}

type shieldNoteFixture struct {
	MasterPublicKey          string               `json:"masterPublicKey"`
	Random                   string               `json:"random"`
	Value                    string               `json:"value"`
	TokenAddress             string               `json:"tokenAddress"`
	TokenData                railcrypto.TokenData `json:"tokenData"`
	ShieldPrivateKey         string               `json:"shieldPrivateKey"`
	ReceiverPrivateKey       string               `json:"receiverPrivateKey"`
	ReceiverViewingPublicKey string               `json:"receiverViewingPublicKey"`
	RandomGCMIV              string               `json:"randomGCMIV"`
	ReceiverCTRIV            string               `json:"receiverCTRIV"`
	Request                  NativeShieldRequest  `json:"request"`
}

type boundParamsV2Fixture struct {
	BoundParams boundParamsV2JSON `json:"boundParams"`
	Hash        string            `json:"hash"`
	HashHex     string            `json:"hashHex"`
}

type boundParamsV3Fixture struct {
	BoundParams boundParamsV3JSON `json:"boundParams"`
	Hash        string            `json:"hash"`
	HashHex     string            `json:"hashHex"`
}

type boundParamsV2JSON struct {
	TreeNumber           string                       `json:"treeNumber"`
	MinGasPrice          string                       `json:"minGasPrice"`
	Unshield             string                       `json:"unshield"`
	ChainID              string                       `json:"chainID"`
	AdaptContract        string                       `json:"adaptContract"`
	AdaptParams          string                       `json:"adaptParams"`
	CommitmentCiphertext []commitmentCiphertextV2JSON `json:"commitmentCiphertext"`
}

type commitmentCiphertextV2JSON struct {
	Ciphertext                []string `json:"ciphertext"`
	BlindedSenderViewingKey   string   `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string   `json:"blindedReceiverViewingKey"`
	AnnotationData            string   `json:"annotationData"`
	Memo                      string   `json:"memo"`
}

type boundParamsV3JSON struct {
	Local  localBoundParamsV3JSON  `json:"local"`
	Global globalBoundParamsV3JSON `json:"global"`
}

type localBoundParamsV3JSON struct {
	TreeNumber           string                       `json:"treeNumber"`
	CommitmentCiphertext []commitmentCiphertextV3JSON `json:"commitmentCiphertext"`
}

type commitmentCiphertextV3JSON struct {
	Ciphertext                string `json:"ciphertext"`
	BlindedSenderViewingKey   string `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string `json:"blindedReceiverViewingKey"`
}

type globalBoundParamsV3JSON struct {
	MinGasPrice      string `json:"minGasPrice"`
	ChainID          string `json:"chainID"`
	SenderCiphertext string `json:"senderCiphertext"`
	To               string `json:"to"`
	Data             string `json:"data"`
}

func TestHashBoundParamsV2MatchesTypeScript(t *testing.T) {
	fixture := loadBoundParamsFixtures(t).V2
	boundParams := mustBoundParamsV2(t, fixture.BoundParams)

	hash, err := HashBoundParamsV2(boundParams)
	if err != nil {
		t.Fatal(err)
	}
	if hash.String() != fixture.Hash {
		t.Fatalf("expected hash %s, got %s", fixture.Hash, hash)
	}
	hashHex, err := HashBoundParamsV2Hex(boundParams, true)
	if err != nil {
		t.Fatal(err)
	}
	if hashHex != fixture.HashHex {
		t.Fatalf("expected hash hex %s, got %s", fixture.HashHex, hashHex)
	}
}

func TestHashBoundParamsV3MatchesTypeScript(t *testing.T) {
	fixture := loadBoundParamsFixtures(t).V3
	boundParams := mustBoundParamsV3(t, fixture.BoundParams)

	hash, err := HashBoundParamsV3(boundParams)
	if err != nil {
		t.Fatal(err)
	}
	if hash.String() != fixture.Hash {
		t.Fatalf("expected hash %s, got %s", fixture.Hash, hash)
	}
	hashHex, err := HashBoundParamsV3Hex(boundParams, true)
	if err != nil {
		t.Fatal(err)
	}
	if hashHex != fixture.HashHex {
		t.Fatalf("expected hash hex %s, got %s", fixture.HashHex, hashHex)
	}
}

func TestCreateCommitmentCiphertextV2MatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	blindedSender := mustHexBytes(t, fixtures.CommitmentCiphertextFixtures.Blinding.BlindedSenderViewingKey)
	blindedReceiver := mustHexBytes(t, fixtures.CommitmentCiphertextFixtures.Blinding.BlindedReceiverViewingKey)

	ciphertext, err := CreateCommitmentCiphertextV2(
		fixtures.TransactNoteFixtures.V2,
		blindedSender,
		blindedReceiver,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, ciphertext.Native(), fixtures.CommitmentCiphertextFixtures.V2)
}

func TestCreateCommitmentCiphertextV3MatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	blindedSender := mustHexBytes(t, fixtures.CommitmentCiphertextFixtures.Blinding.BlindedSenderViewingKey)
	blindedReceiver := mustHexBytes(t, fixtures.CommitmentCiphertextFixtures.Blinding.BlindedReceiverViewingKey)

	ciphertext, err := CreateCommitmentCiphertextV3(
		fixtures.TransactNoteFixtures.V3,
		blindedSender,
		blindedReceiver,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, ciphertext.Native(), fixtures.CommitmentCiphertextFixtures.V3)
}

func TestSpendingSolutionsMatchTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).SpendingSolutionFixtures
	simpleTreeBalance := mustNativeTreeBalance(t, fixture.Inputs.SimpleTreeBalance)
	exact := FindExactSolutionsOverTargetValue(simpleTreeBalance, mustBigInt(t, "65"))
	assertJSONEqual(t, nativeSolutionTXOsFrom(exact), fixture.Exact)

	simpleGroup, err := CreateSimpleSatisfyingUTXOGroup(
		[]TreeBalance{simpleTreeBalance},
		mustBigInt(t, fixture.Inputs.SimpleRequired),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeSimpleUTXOGroupFrom(simpleGroup), fixture.SimpleGroup)

	complexTreeBalance := mustNativeTreeBalance(t, fixture.Inputs.ComplexTreeBalance)
	outputs := make([]SolutionOutput, len(fixture.Inputs.ComplexOutputs))
	for i, output := range fixture.Inputs.ComplexOutputs {
		outputs[i] = SolutionOutput{
			ID:        output.ID,
			Value:     mustBigInt(t, output.Value),
			TokenData: fixture.Inputs.TokenData,
		}
	}
	complexGroups, remainingOutputs, excluded, err := CreateSpendingSolutionsForValue(
		[]TreeBalance{complexTreeBalance},
		outputs,
		nil,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeSpendingSolutionGroupsFrom(complexGroups), fixture.ComplexGroups)
	if remainingOutputs == nil {
		remainingOutputs = []SolutionOutput{}
	}
	assertJSONEqual(t, nativeSolutionOutputsFrom(remainingOutputs), fixture.ComplexRemainingOutputs)
	assertJSONEqual(t, excluded, fixture.ComplexExcluded)

	walletViewingPublicKey := mustHexBytes(t, fixture.Inputs.WalletAddressData.ViewingPublicKey)
	changeOutput, notePublicKey, hash, err := CreateChangeOutput(
		mustBigInt(t, fixture.Inputs.WalletAddressData.MasterPublicKey),
		walletViewingPublicKey,
		complexGroups[0],
		fixture.Inputs.ChangeRandom,
		fixture.Inputs.WalletSource,
	)
	if err != nil {
		t.Fatal(err)
	}
	change := nativeChangeOutputFrom(t, changeOutput, notePublicKey, hash)
	assertJSONEqual(t, change, fixture.ChangeOutput)
}

func TestGenerateTransactionRequestV2MatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).TransactionRequestFixtures
	inputs := mustTransactionRequestInputs(t, fixture.Inputs)

	request, err := GenerateTransactionRequestV2(inputs)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, request.Native(), fixture.V2)
}

func TestGenerateTransactionRequestV3MatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).TransactionRequestFixtures
	inputs := mustTransactionRequestInputs(t, fixture.Inputs)

	request, err := GenerateTransactionRequestV3(inputs)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, request.Native(), fixture.V3)
}

func TestCreateDummyProvedTransactionV2MatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).TransactionRequestFixtures
	inputs := mustTransactionRequestInputs(t, fixture.Inputs)
	request, err := GenerateTransactionRequestV2(inputs)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := CreateDummyProvedTransactionV2(request)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, tx.Native(), fixture.DummyV2)
}

func TestCreateDummyProvedTransactionV3MatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).TransactionRequestFixtures
	inputs := mustTransactionRequestInputs(t, fixture.Inputs)
	request, err := GenerateTransactionRequestV3(inputs)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := CreateDummyProvedTransactionV3(request)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, tx.Native(), fixture.DummyV3)
}

func TestGenerateDummyTransactionBatchV2MatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).DummyBatchFixtures
	inputs := mustDummyBatchInputs(t, fixture.Inputs)

	txs, err := GenerateDummyTransactionsV2(inputs)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeTransactionStructV2Slice(txs), fixture.V2)
}

func TestGenerateUnprovedTransactionBatchV2MatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).DummyBatchFixtures
	inputs := mustDummyBatchInputs(t, fixture.Inputs)
	privateKey := mustHexBytes(t, fixture.Inputs.SpendingPrivateKey)

	txs, err := GenerateUnprovedTransactionsV2(inputs, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeUnprovedTransactionV2Slice(txs), fixture.UnprovedV2)
}

func TestProveUnprovedTransactionV2MatchesDummyFixture(t *testing.T) {
	fixture := loadExportedFixtures(t).DummyBatchFixtures
	inputs := mustDummyBatchInputs(t, fixture.Inputs)
	privateKey := mustHexBytes(t, fixture.Inputs.SpendingPrivateKey)
	unproved, err := GenerateUnprovedTransactionsV2(inputs, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	prover := railproof.NewProver(testArtifactGetter{}, testProofBackend{})

	tx, err := ProveUnprovedTransactionV2(context.Background(), prover, unproved[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, tx.Native(), fixture.V2[0])
}

func TestGenerateProvedTransactionBatchV2MatchesDummyFixture(t *testing.T) {
	fixture := loadExportedFixtures(t).DummyBatchFixtures
	inputs := mustDummyBatchInputs(t, fixture.Inputs)
	privateKey := mustHexBytes(t, fixture.Inputs.SpendingPrivateKey)
	prover := railproof.NewProver(testArtifactGetter{}, testProofBackend{})

	txs, err := GenerateProvedTransactionsV2(context.Background(), prover, inputs, privateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeTransactionStructV2Slice(txs), fixture.V2)
}

func TestGenerateDummyTransactionBatchV3MatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).DummyBatchFixtures
	inputs := mustDummyBatchInputs(t, fixture.Inputs)

	txs, err := GenerateDummyTransactionsV3(inputs)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeTransactionStructV3Slice(txs), fixture.V3)
}

func TestGenerateUnprovedTransactionBatchV3MatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).DummyBatchFixtures
	inputs := mustDummyBatchInputs(t, fixture.Inputs)
	privateKey := mustHexBytes(t, fixture.Inputs.SpendingPrivateKey)

	txs, err := GenerateUnprovedTransactionsV3(inputs, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeUnprovedTransactionV3Slice(txs), fixture.UnprovedV3)
}

func TestProveUnprovedTransactionV3MatchesDummyFixture(t *testing.T) {
	fixture := loadExportedFixtures(t).DummyBatchFixtures
	inputs := mustDummyBatchInputs(t, fixture.Inputs)
	privateKey := mustHexBytes(t, fixture.Inputs.SpendingPrivateKey)
	unproved, err := GenerateUnprovedTransactionsV3(inputs, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	prover := railproof.NewProver(testArtifactGetter{}, testProofBackend{})

	tx, err := ProveUnprovedTransactionV3(context.Background(), prover, unproved[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, tx.Native(), fixture.V3[0])
}

func TestGenerateProvedTransactionBatchV3MatchesDummyFixture(t *testing.T) {
	fixture := loadExportedFixtures(t).DummyBatchFixtures
	inputs := mustDummyBatchInputs(t, fixture.Inputs)
	privateKey := mustHexBytes(t, fixture.Inputs.SpendingPrivateKey)
	prover := railproof.NewProver(testArtifactGetter{}, testProofBackend{})

	txs, err := GenerateProvedTransactionsV3(context.Background(), prover, inputs, privateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeTransactionStructV3Slice(txs), fixture.V3)
}

func TestCreateTransactionStructV2MatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	expected := fixtures.TransactionStructFixtures.V2

	tx := mustSampleTransactionV2(t, fixtures)
	assertJSONEqual(t, tx.Native(), expected)
}

func TestCreateTransactionStructV3MatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	expected := fixtures.TransactionStructFixtures.V3

	tx := mustSampleTransactionV3(t, fixtures)
	assertJSONEqual(t, tx.Native(), expected)
}

func TestEncodeTransactV2CalldataMatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	tx := mustSampleTransactionV2(t, fixtures)

	calldata, err := EncodeTransactV2Calldata([]TransactionStructV2{tx})
	if err != nil {
		t.Fatal(err)
	}
	if calldata != fixtures.CalldataFixtures.V2Transact {
		t.Fatalf("expected calldata %s, got %s", fixtures.CalldataFixtures.V2Transact, calldata)
	}
}

func TestDecodeTransactV2CalldataMatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	expected := mustSampleTransactionV2(t, fixtures)

	txs, err := DecodeTransactV2Calldata(fixtures.CalldataFixtures.V2Transact)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeTransactionStructV2Slice(txs), []NativeTransactionStructV2{expected.Native()})
}

func TestEncodeExecuteV3TransactCalldataMatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	tx := mustSampleTransactionV3(t, fixtures)

	calldata, err := EncodeExecuteV3TransactCalldata([]TransactionStructV3{tx})
	if err != nil {
		t.Fatal(err)
	}
	if calldata != fixtures.CalldataFixtures.V3ExecuteTransact {
		t.Fatalf("expected calldata %s, got %s", fixtures.CalldataFixtures.V3ExecuteTransact, calldata)
	}
}

func TestDecodeExecuteV3TransactCalldataMatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	expected := mustSampleTransactionV3(t, fixtures)

	txs, globalBoundParams, err := DecodeExecuteV3TransactCalldata(fixtures.CalldataFixtures.V3ExecuteTransact)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, (BoundParamsV3{Global: globalBoundParams}).Native().Global, expected.BoundParams.Native().Global)
	assertJSONEqual(t, nativeTransactionStructV3Slice(txs), []NativeTransactionStructV3{expected.Native()})
}

func TestShieldRequestNativeMatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).ShieldFixtures
	request := mustShieldRequest(t, fixture.Request)

	assertJSONEqual(t, request.Native(), fixture.Request)
}

func TestCreateShieldNoteRequestMatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).ShieldFixtures.ShieldNote
	shieldPrivateKey := mustHexBytes(t, fixture.ShieldPrivateKey)
	receiverViewingPublicKey := mustHexBytes(t, fixture.ReceiverViewingPublicKey)

	request, err := CreateShieldNoteRequest(ShieldNoteInputs{
		MasterPublicKey:          mustBigInt(t, fixture.MasterPublicKey),
		Random:                   fixture.Random,
		Value:                    mustBigInt(t, fixture.Value),
		TokenData:                fixture.TokenData,
		ShieldPrivateKey:         shieldPrivateKey,
		ReceiverViewingPublicKey: receiverViewingPublicKey,
		RandomGCMIV:              fixture.RandomGCMIV,
		ReceiverCTRIV:            fixture.ReceiverCTRIV,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, request.Native(), fixture.Request)
}

func TestDecryptShieldRandomMatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).ShieldFixtures.ShieldNote
	receiverPrivateKey := mustHexBytes(t, fixture.ReceiverPrivateKey)
	shieldKey := mustHexBytes(t, fixture.Request.Ciphertext.ShieldKey)
	sharedKey, err := railcrypto.SharedSymmetricKey(receiverPrivateKey, shieldKey)
	if err != nil {
		t.Fatal(err)
	}
	random, err := DecryptShieldRandom(fixture.Request.Ciphertext.EncryptedBundle, sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	if random != fixture.Random {
		t.Fatalf("expected decrypted shield random %s, got %s", fixture.Random, random)
	}
}

func TestEncodeShieldV2CalldataMatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).ShieldFixtures
	request := mustShieldRequest(t, fixture.Request)

	calldata, err := EncodeShieldV2Calldata([]ShieldRequest{request})
	if err != nil {
		t.Fatal(err)
	}
	if calldata != fixture.V2ShieldCalldata {
		t.Fatalf("expected calldata %s, got %s", fixture.V2ShieldCalldata, calldata)
	}
}

func TestEncodeExecuteV3ShieldCalldataMatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).ShieldFixtures
	request := mustShieldRequest(t, fixture.Request)

	calldata, err := EncodeExecuteV3ShieldCalldata([]ShieldRequest{request}, mustBigInt(t, fixture.ChainID))
	if err != nil {
		t.Fatal(err)
	}
	if calldata != fixture.V3ExecuteShieldCalldata {
		t.Fatalf("expected calldata %s, got %s", fixture.V3ExecuteShieldCalldata, calldata)
	}
}

func mustSampleTransactionV2(t *testing.T, fixtures exportedFixtures) TransactionStructV2 {
	t.Helper()
	expected := fixtures.TransactionStructFixtures.V2
	boundParams := mustBoundParamsV2(t, fixtures.BoundParamsFixtures.V2.BoundParams)

	tx, err := CreateTransactionStructV2(
		sampleProof(),
		railproof.PublicInputsRailgun{
			MerkleRoot:     mustBigInt(t, "1"),
			Nullifiers:     []*big.Int{mustBigInt(t, "2"), mustBigInt(t, "3")},
			CommitmentsOut: []*big.Int{mustBigInt(t, "4"), mustBigInt(t, "5"), mustBigInt(t, "6")},
		},
		boundParams,
		CommitmentPreimage{
			NPK:   expected.UnshieldPreimage.NPK,
			Token: expected.UnshieldPreimage.Token,
			Value: mustBigInt(t, expected.UnshieldPreimage.Value),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func mustSampleTransactionV3(t *testing.T, fixtures exportedFixtures) TransactionStructV3 {
	t.Helper()
	expected := fixtures.TransactionStructFixtures.V3
	boundParams := mustBoundParamsV3(t, fixtures.BoundParamsFixtures.V3.BoundParams)

	tx, err := CreateTransactionStructV3(
		sampleProof(),
		railproof.PublicInputsRailgun{
			MerkleRoot:     mustBigInt(t, "11"),
			Nullifiers:     []*big.Int{mustBigInt(t, "12"), mustBigInt(t, "13")},
			CommitmentsOut: []*big.Int{mustBigInt(t, "14"), mustBigInt(t, "15")},
		},
		boundParams,
		CommitmentPreimage{
			NPK:   expected.UnshieldPreimage.NPK,
			Token: expected.UnshieldPreimage.Token,
			Value: mustBigInt(t, expected.UnshieldPreimage.Value),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func mustShieldRequest(t *testing.T, raw NativeShieldRequest) ShieldRequest {
	t.Helper()
	return ShieldRequest{
		Preimage: CommitmentPreimage{
			NPK:   raw.Preimage.NPK,
			Token: raw.Preimage.Token,
			Value: mustBigInt(t, raw.Preimage.Value),
		},
		Ciphertext: ShieldCiphertext{
			EncryptedBundle: raw.Ciphertext.EncryptedBundle,
			ShieldKey:       raw.Ciphertext.ShieldKey,
		},
	}
}

func mustTransactionRequestInputs(t *testing.T, raw transactionRequestInputsFixture) TransactionRequestInputs {
	t.Helper()
	senderViewingPrivateKey := mustHexBytes(t, raw.SenderViewingPrivateKey)
	senderViewingPublicKey := mustHexBytes(t, raw.SenderViewingPublicKey)
	receiverViewingPublicKey := mustHexBytes(t, raw.ReceiverViewingPublicKey)
	utxos := make([]RequestUTXO, len(raw.UTXOs))
	for i, utxo := range raw.UTXOs {
		utxos[i] = RequestUTXO{
			Position:            mustUint(t, utxo.Position),
			NoteRandom:          utxo.NoteRandom,
			NoteValue:           mustBigInt(t, utxo.NoteValue),
			MerkleProofElements: append([]string(nil), raw.MerkleProofElements...),
		}
	}
	outputs := make([]RequestTransactOutput, len(raw.Outputs))
	for i, output := range raw.Outputs {
		outputs[i] = RequestTransactOutput{
			ReceiverMasterPublicKey:  mustBigInt(t, raw.ReceiverMasterPublicKey),
			ReceiverViewingPublicKey: receiverViewingPublicKey,
			Random:                   output.Random,
			Value:                    mustBigInt(t, output.Value),
			TokenData:                raw.TokenData,
			SenderRandom:             output.SenderRandom,
			OutputType:               output.OutputType,
			WalletSource:             output.WalletSource,
			MemoText:                 output.MemoText,
		}
	}
	to, err := AddressFromHex(raw.GlobalBoundParams.To)
	if err != nil {
		t.Fatal(err)
	}
	return TransactionRequestInputs{
		Chain:                   raw.Chain,
		SpendingTree:            uint32(mustUint(t, raw.SpendingTree)),
		MerkleRoot:              raw.MerkleRoot,
		TokenData:               raw.TokenData,
		UTXOs:                   utxos,
		Outputs:                 outputs,
		SpendingPublicKey:       [2]*big.Int{mustBigInt(t, raw.SpendingPublicKey[0]), mustBigInt(t, raw.SpendingPublicKey[1])},
		NullifyingKey:           mustBigInt(t, raw.NullifyingKey),
		SenderMasterPublicKey:   mustBigInt(t, raw.SenderMasterPublicKey),
		SenderViewingPrivateKey: senderViewingPrivateKey,
		SenderViewingPublicKey:  senderViewingPublicKey,
		AdaptID:                 raw.AdaptID,
		MinGasPrice:             mustBigInt(t, raw.MinGasPrice),
		GlobalBoundParams: GlobalBoundParamsV3{
			MinGasPrice:      mustBigInt(t, raw.GlobalBoundParams.MinGasPrice),
			ChainID:          mustBigInt(t, raw.GlobalBoundParams.ChainID),
			SenderCiphertext: mustDynamicBytes(t, raw.GlobalBoundParams.SenderCiphertext),
			To:               to,
			Data:             mustDynamicBytes(t, raw.GlobalBoundParams.Data),
		},
		NoteCiphertextV2IVs:    []string{raw.V2NoteCiphertextIV},
		AnnotationV2IVs:        []string{raw.V2AnnotationIV},
		NoteCiphertextV3Nonces: []string{raw.V3NoteCiphertextNonce},
	}
}

func mustDummyBatchInputs(t *testing.T, raw dummyBatchInputsFixture) DummyTransactionBatchInputs {
	t.Helper()
	walletViewingPrivateKey := mustHexBytes(t, raw.WalletViewingPrivateKey)
	walletViewingPublicKey := mustHexBytes(t, raw.WalletViewingPublicKey)
	receiverViewingPublicKey := mustHexBytes(t, raw.ReceiverViewingPublicKey)
	utxos := make([]BatchUTXO, len(raw.UTXOs))
	for i, utxo := range raw.UTXOs {
		utxos[i] = BatchUTXO{
			Position:            mustUint(t, utxo.Position),
			NoteRandom:          utxo.NoteRandom,
			Value:               mustBigInt(t, utxo.NoteValue),
			MerkleProofElements: append([]string(nil), raw.MerkleProofElements...),
		}
	}
	outputs := make([]RequestTransactOutput, len(raw.Outputs))
	for i, output := range raw.Outputs {
		outputs[i] = RequestTransactOutput{
			ReceiverMasterPublicKey:  mustBigInt(t, raw.ReceiverMasterPublicKey),
			ReceiverViewingPublicKey: receiverViewingPublicKey,
			Random:                   output.Random,
			Value:                    mustBigInt(t, output.Value),
			TokenData:                raw.TokenData,
			SenderRandom:             output.SenderRandom,
			OutputType:               output.OutputType,
			WalletSource:             output.WalletSource,
			MemoText:                 output.MemoText,
		}
	}
	to, err := AddressFromHex(raw.GlobalBoundParams.To)
	if err != nil {
		t.Fatal(err)
	}
	return DummyTransactionBatchInputs{
		Chain:                   raw.Chain,
		OverallBatchMinGasPrice: mustBigInt(t, raw.OverallBatchMinGasPrice),
		AdaptID:                 raw.AdaptID,
		Wallet: BatchWallet{
			MasterPublicKey:   mustBigInt(t, raw.WalletMasterPublicKey),
			ViewingPrivateKey: walletViewingPrivateKey,
			ViewingPublicKey:  walletViewingPublicKey,
			SpendingPublicKey: [2]*big.Int{mustBigInt(t, raw.SpendingPublicKey[0]), mustBigInt(t, raw.SpendingPublicKey[1])},
			NullifyingKey:     mustBigInt(t, raw.NullifyingKey),
			WalletSource:      raw.WalletSource,
		},
		Groups: []DummyTransactionGroup{{
			SpendingTree: uint32(mustUint(t, raw.SpendingTree)),
			MerkleRoot:   raw.MerkleRoot,
			TokenData:    raw.TokenData,
			UTXOs:        utxos,
			Outputs:      outputs,
		}},
		GlobalBoundParams: GlobalBoundParamsV3{
			MinGasPrice:      mustBigInt(t, raw.GlobalBoundParams.MinGasPrice),
			ChainID:          mustBigInt(t, raw.GlobalBoundParams.ChainID),
			SenderCiphertext: mustDynamicBytes(t, raw.GlobalBoundParams.SenderCiphertext),
			To:               to,
			Data:             mustDynamicBytes(t, raw.GlobalBoundParams.Data),
		},
		NoteCiphertextV2IVs:    [][]string{append([]string(nil), raw.V2NoteCiphertextIVs...)},
		AnnotationV2IVs:        [][]string{append([]string(nil), raw.V2AnnotationIVs...)},
		NoteCiphertextV3Nonces: [][]string{append([]string(nil), raw.V3NoteCiphertextNonces...)},
		ChangeRandoms:          []string{raw.ChangeRandom},
	}
}

func mustNativeTreeBalance(t *testing.T, raw nativeTreeBalance) TreeBalance {
	t.Helper()
	utxos := make([]SolutionTXO, len(raw.UTXOs))
	for i, utxo := range raw.UTXOs {
		utxos[i] = SolutionTXO{
			ID:       utxo.ID,
			TXID:     utxo.TXID,
			Tree:     int(mustUint(t, utxo.Tree)),
			Position: mustUint(t, utxo.Position),
			Value:    mustBigInt(t, utxo.Value),
		}
	}
	return TreeBalance{
		Balance: mustBigInt(t, raw.Balance),
		UTXOs:   utxos,
	}
}

func nativeSolutionTXOsFrom(utxos []SolutionTXO) []nativeSolutionTXO {
	out := make([]nativeSolutionTXO, len(utxos))
	for i, utxo := range utxos {
		out[i] = nativeSolutionTXO{
			ID:       utxo.ID,
			TXID:     utxo.TXID,
			Tree:     strconv.Itoa(utxo.Tree),
			Position: strconv.FormatUint(utxo.Position, 10),
			Value:    utxo.Value.String(),
		}
	}
	return out
}

func nativeSimpleUTXOGroupFrom(group SimpleUTXOGroup) nativeSimpleUTXOGroup {
	return nativeSimpleUTXOGroup{
		SpendingTree: strconv.Itoa(group.SpendingTree),
		Amount:       group.Amount.String(),
		UTXOs:        nativeSolutionTXOsFrom(group.UTXOs),
	}
}

func nativeSpendingSolutionGroupsFrom(groups []SpendingSolutionGroup) []nativeSpendingSolutionGroup {
	out := make([]nativeSpendingSolutionGroup, len(groups))
	for i, group := range groups {
		out[i] = nativeSpendingSolutionGroup{
			SpendingTree:  strconv.Itoa(group.SpendingTree),
			UTXOs:         nativeSolutionTXOsFrom(group.UTXOs),
			TokenOutputs:  nativeSolutionOutputsFrom(group.TokenOutputs),
			UnshieldValue: group.UnshieldValue.String(),
			TokenData:     group.TokenData,
		}
	}
	return out
}

func nativeSolutionOutputsFrom(outputs []SolutionOutput) []nativeSolutionOutput {
	out := make([]nativeSolutionOutput, len(outputs))
	for i, output := range outputs {
		out[i] = nativeSolutionOutput{Value: output.Value.String()}
	}
	return out
}

func nativeChangeOutputFrom(t *testing.T, output RequestTransactOutput, notePublicKey *big.Int, hash *big.Int) nativeChangeOutput {
	t.Helper()
	tokenHash, err := railcrypto.TokenDataHash(output.TokenData)
	if err != nil {
		t.Fatal(err)
	}
	return nativeChangeOutput{
		Random:                    output.Random,
		Value:                     output.Value.String(),
		TokenHash:                 tokenHash,
		NotePublicKey:             notePublicKey.String(),
		Hash:                      hash.String(),
		OutputType:                output.OutputType,
		WalletSource:              output.WalletSource,
		SenderRandom:              output.SenderRandom,
		RecipientMasterPublicKey:  output.ReceiverMasterPublicKey.String(),
		RecipientViewingPublicKey: railcrypto.BytesToHex(output.ReceiverViewingPublicKey, false),
	}
}

func nativeTransactionStructV2Slice(txs []TransactionStructV2) []NativeTransactionStructV2 {
	out := make([]NativeTransactionStructV2, len(txs))
	for i, tx := range txs {
		out[i] = tx.Native()
	}
	return out
}

func nativeTransactionStructV3Slice(txs []TransactionStructV3) []NativeTransactionStructV3 {
	out := make([]NativeTransactionStructV3, len(txs))
	for i, tx := range txs {
		out[i] = tx.Native()
	}
	return out
}

func nativeUnprovedTransactionV2Slice(txs []UnprovedTransactionV2) []nativeUnprovedTransactionV2 {
	out := make([]nativeUnprovedTransactionV2, len(txs))
	for i, tx := range txs {
		out[i] = nativeUnprovedTransactionV2{
			Request:   tx.Request.Native(),
			Signature: nativeSignatureFrom(tx.Signature),
		}
	}
	return out
}

func nativeUnprovedTransactionV3Slice(txs []UnprovedTransactionV3) []nativeUnprovedTransactionV3 {
	out := make([]nativeUnprovedTransactionV3, len(txs))
	for i, tx := range txs {
		out[i] = nativeUnprovedTransactionV3{
			Request:   tx.Request.Native(),
			Signature: nativeSignatureFrom(tx.Signature),
		}
	}
	return out
}

func nativeSignatureFrom(signature [3]*big.Int) [3]string {
	return [3]string{
		signature[0].String(),
		signature[1].String(),
		signature[2].String(),
	}
}

type testArtifactGetter struct{}

func (testArtifactGetter) AssertArtifactExists(_ int, _ int) error {
	return nil
}

func (testArtifactGetter) GetArtifacts(_ context.Context, _ railproof.PublicInputsRailgun) (railproof.Artifact, error) {
	return railproof.Artifact{}, nil
}

func (testArtifactGetter) GetArtifactsPOI(_ context.Context, _ int, _ int) (railproof.Artifact, error) {
	return railproof.Artifact{}, nil
}

type testProofBackend struct{}

func (testProofBackend) ProveRailgun(_ context.Context, _ railproof.CircuitID, inputs railproof.FormattedCircuitInputsRailgun, _ railproof.Artifact, _ railproof.ProgressCallback) (railproof.ProofResult, error) {
	signals := make([]*big.Int, 0, 2+len(inputs.Nullifiers)+len(inputs.CommitmentsOut))
	signals = append(signals, inputs.MerkleRoot, inputs.BoundParamsHash)
	signals = append(signals, inputs.Nullifiers...)
	signals = append(signals, inputs.CommitmentsOut...)
	return railproof.ProofResult{Proof: ZeroProof(), PublicSignals: signals}, nil
}

func (testProofBackend) VerifyRailgun(_ context.Context, _ railproof.PublicInputsRailgun, _ railproof.Proof, _ railproof.Artifact) (bool, error) {
	return true, nil
}

func (testProofBackend) ProvePOI(_ context.Context, _ railproof.CircuitID, _ railproof.FormattedCircuitInputsPOI, _ railproof.Artifact, _ railproof.ProgressCallback) (railproof.ProofResult, error) {
	return railproof.ProofResult{Proof: ZeroProof()}, nil
}

func (testProofBackend) VerifyPOI(_ context.Context, _ railproof.PublicInputsPOI, _ railproof.Proof, _ railproof.Artifact) (bool, error) {
	return true, nil
}

func loadBoundParamsFixtures(t *testing.T) boundParamsFixtureSet {
	t.Helper()
	return loadExportedFixtures(t).BoundParamsFixtures
}

func loadExportedFixtures(t *testing.T) exportedFixtures {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func mustBoundParamsV2(t *testing.T, raw boundParamsV2JSON) BoundParamsV2 {
	t.Helper()
	adaptContract, err := AddressFromHex(raw.AdaptContract)
	if err != nil {
		t.Fatal(err)
	}
	adaptParams := mustBytes32(t, raw.AdaptParams)
	ciphertexts := make([]CommitmentCiphertextV2, len(raw.CommitmentCiphertext))
	for i, ciphertext := range raw.CommitmentCiphertext {
		if len(ciphertext.Ciphertext) != 4 {
			t.Fatalf("expected 4 ciphertext chunks, got %d", len(ciphertext.Ciphertext))
		}
		for j, chunk := range ciphertext.Ciphertext {
			ciphertexts[i].Ciphertext[j] = mustBytes32(t, chunk)
		}
		ciphertexts[i].BlindedSenderViewingKey = mustBytes32(t, ciphertext.BlindedSenderViewingKey)
		ciphertexts[i].BlindedReceiverViewingKey = mustBytes32(t, ciphertext.BlindedReceiverViewingKey)
		ciphertexts[i].AnnotationData = mustDynamicBytes(t, ciphertext.AnnotationData)
		ciphertexts[i].Memo = mustDynamicBytes(t, ciphertext.Memo)
	}
	return BoundParamsV2{
		TreeNumber:           uint16(mustUint(t, raw.TreeNumber)),
		MinGasPrice:          mustBigInt(t, raw.MinGasPrice),
		Unshield:             uint8(mustUint(t, raw.Unshield)),
		ChainID:              mustUint(t, raw.ChainID),
		AdaptContract:        adaptContract,
		AdaptParams:          adaptParams,
		CommitmentCiphertext: ciphertexts,
	}
}

func mustBoundParamsV3(t *testing.T, raw boundParamsV3JSON) BoundParamsV3 {
	t.Helper()
	ciphertexts := make([]CommitmentCiphertextV3, len(raw.Local.CommitmentCiphertext))
	for i, ciphertext := range raw.Local.CommitmentCiphertext {
		ciphertexts[i] = CommitmentCiphertextV3{
			Ciphertext:                mustDynamicBytes(t, ciphertext.Ciphertext),
			BlindedSenderViewingKey:   mustBytes32(t, ciphertext.BlindedSenderViewingKey),
			BlindedReceiverViewingKey: mustBytes32(t, ciphertext.BlindedReceiverViewingKey),
		}
	}
	to, err := AddressFromHex(raw.Global.To)
	if err != nil {
		t.Fatal(err)
	}
	return BoundParamsV3{
		Local: LocalBoundParamsV3{
			TreeNumber:           uint32(mustUint(t, raw.Local.TreeNumber)),
			CommitmentCiphertext: ciphertexts,
		},
		Global: GlobalBoundParamsV3{
			MinGasPrice:      mustBigInt(t, raw.Global.MinGasPrice),
			ChainID:          mustBigInt(t, raw.Global.ChainID),
			SenderCiphertext: mustDynamicBytes(t, raw.Global.SenderCiphertext),
			To:               to,
			Data:             mustDynamicBytes(t, raw.Global.Data),
		},
	}
}

func mustUint(t *testing.T, value string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mustBigInt(t *testing.T, value string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid bigint %s", value)
	}
	return n
}

func mustBytes32(t *testing.T, value string) [32]byte {
	t.Helper()
	out, err := Bytes32FromHex(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustDynamicBytes(t *testing.T, value string) []byte {
	t.Helper()
	out, err := DynamicBytesFromHex(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustHexBytes(t *testing.T, value string) []byte {
	t.Helper()
	out, err := railcrypto.HexToBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sampleProof() railproof.Proof {
	return railproof.Proof{
		PiA: [2]string{"1", "2"},
		PiB: [2][2]string{{"3", "4"}, {"5", "6"}},
		PiC: [2]string{"7", "8"},
	}
}

func assertJSONEqual(t *testing.T, got any, expected any) {
	t.Helper()
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(expectedJSON) {
		gotPretty, _ := json.MarshalIndent(got, "", "  ")
		expectedPretty, _ := json.MarshalIndent(expected, "", "  ")
		t.Fatalf("mismatch\nexpected:\n%s\nactual:\n%s", expectedPretty, gotPretty)
	}
}
