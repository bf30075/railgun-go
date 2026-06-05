package validation

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func TestExtractRailgunTransactionDataFromCalldataMatchesTypeScript(t *testing.T) {
	fixture := loadValidationFixtures(t)
	receiver := mustReceiverViewingData(t, fixture.Inputs)

	v2, err := ExtractRailgunTransactionDataFromTransactV2Calldata(
		ContractTransactionRequest{To: fixture.Calldata.ContractAddress, Data: fixture.Calldata.V2},
		fixture.Calldata.ContractAddress,
		receiver,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeExtractedData(v2), fixture.Validation.ExtractedV2)

	relayV2, err := ExtractRailgunTransactionDataFromRelayAdaptV2Calldata(
		ContractTransactionRequest{To: fixture.Calldata.ContractAddress, Data: fixture.Calldata.RelayV2},
		fixture.Calldata.ContractAddress,
		receiver,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeExtractedData(relayV2), fixture.Validation.ExtractedRelayV2)

	v3, err := ExtractRailgunTransactionDataFromExecuteV3Calldata(
		ContractTransactionRequest{To: fixture.Calldata.ContractAddress, Data: fixture.Calldata.V3},
		fixture.Calldata.ContractAddress,
		receiver,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeExtractedData(v3), fixture.Validation.ExtractedV3)
}

func TestExtractFirstNoteERC20AmountMapFromCalldataMatchesTypeScript(t *testing.T) {
	fixture := loadValidationFixtures(t)
	receiver := mustReceiverViewingData(t, fixture.Inputs)

	v2, err := ExtractFirstNoteERC20AmountMapFromTransactV2Calldata(
		ContractTransactionRequest{To: fixture.Calldata.ContractAddress, Data: fixture.Calldata.V2},
		fixture.Calldata.ContractAddress,
		receiver,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeAmountMap(v2), fixture.Validation.ERC20AmountMapV2)

	relayV2, err := ExtractFirstNoteERC20AmountMapFromRelayAdaptV2Calldata(
		ContractTransactionRequest{To: fixture.Calldata.ContractAddress, Data: fixture.Calldata.RelayV2},
		fixture.Calldata.ContractAddress,
		receiver,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeAmountMap(relayV2), fixture.Validation.ERC20AmountMapRelayV2)

	v3, err := ExtractFirstNoteERC20AmountMapFromExecuteV3Calldata(
		ContractTransactionRequest{To: fixture.Calldata.ContractAddress, Data: fixture.Calldata.V3},
		fixture.Calldata.ContractAddress,
		receiver,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nativeAmountMap(v3), fixture.Validation.ERC20AmountMapV3)
}

type exportedFixtures struct {
	DummyBatchFixtures    dummyBatchFixtureSet    `json:"dummyBatchFixtures"`
	POIValidationFixtures poiValidationFixtureSet `json:"poiValidationFixtures"`
}

type dummyBatchFixtureSet struct {
	Inputs     dummyBatchInputsFixture `json:"inputs"`
	Calldata   dummyBatchCalldata      `json:"calldata"`
	Validation validationFixtureSet    `json:"validation"`
}

type dummyBatchInputsFixture struct {
	ReceiverMasterPublicKey   string `json:"receiverMasterPublicKey"`
	ReceiverViewingPublicKey  string `json:"receiverViewingPublicKey"`
	ReceiverViewingPrivateKey string `json:"receiverViewingPrivateKey"`
}

type dummyBatchCalldata struct {
	ContractAddress string `json:"contractAddress"`
	V2              string `json:"v2"`
	RelayV2         string `json:"relayV2"`
	V3              string `json:"v3"`
}

type validationFixtureSet struct {
	ExtractedV2           []nativeExtractedDatum `json:"extractedV2"`
	ExtractedRelayV2      []nativeExtractedDatum `json:"extractedRelayV2"`
	ExtractedV3           []nativeExtractedDatum `json:"extractedV3"`
	ERC20AmountMapV2      map[string]string      `json:"erc20AmountMapV2"`
	ERC20AmountMapRelayV2 map[string]string      `json:"erc20AmountMapRelayV2"`
	ERC20AmountMapV3      map[string]string      `json:"erc20AmountMapV3"`
}

type nativeExtractedDatum struct {
	RailgunTxid                  string `json:"railgunTxid"`
	UTXOTreeIn                   string `json:"utxoTreeIn"`
	FirstCommitmentNotePublicKey string `json:"firstCommitmentNotePublicKey,omitempty"`
	FirstCommitment              string `json:"firstCommitment"`
}

func nativeExtractedData(values []ExtractedRailgunTransactionData) []nativeExtractedDatum {
	out := make([]nativeExtractedDatum, len(values))
	for i, value := range values {
		native := nativeExtractedDatum{
			RailgunTxid:     value.RailgunTxid,
			UTXOTreeIn:      value.UTXOTreeIn.String(),
			FirstCommitment: value.FirstCommitment,
		}
		if value.FirstCommitmentNotePublicKey != nil {
			native.FirstCommitmentNotePublicKey = value.FirstCommitmentNotePublicKey.String()
		}
		out[i] = native
	}
	return out
}

func nativeAmountMap(values map[string]*big.Int) map[string]string {
	out := make(map[string]string, len(values))
	for tokenAddress, amount := range values {
		out[tokenAddress] = amount.String()
	}
	return out
}

func mustReceiverViewingData(t *testing.T, inputs dummyBatchInputsFixture) ReceiverViewingData {
	t.Helper()
	viewingPrivateKey, err := railcrypto.HexToBytes(inputs.ReceiverViewingPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	viewingPublicKey, err := railcrypto.HexToBytes(inputs.ReceiverViewingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return ReceiverViewingData{
		MasterPublicKey:   mustBigInt(t, inputs.ReceiverMasterPublicKey),
		ViewingPrivateKey: viewingPrivateKey,
		ViewingPublicKey:  viewingPublicKey,
	}
}

func mustBigInt(t *testing.T, value string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid decimal bigint %q", value)
	}
	return n
}

func loadValidationFixtures(t *testing.T) dummyBatchFixtureSet {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.DummyBatchFixtures
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
		t.Fatalf("expected %s, got %s", expectedJSON, gotJSON)
	}
}
