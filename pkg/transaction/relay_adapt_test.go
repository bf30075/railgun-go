package transaction

import (
	"math/big"
	"strconv"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func TestRelayAdaptParamsMatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).RelayAdaptFixtures.Params
	calls := make([]RelayAdaptCall, len(fixture.Calls))
	for i, call := range fixture.Calls {
		relayCall, err := NewRelayAdaptCall(call.To, call.Data, mustBigInt(t, call.Value))
		if err != nil {
			t.Fatal(err)
		}
		calls[i] = relayCall
	}
	actionData, err := NewRelayAdaptActionData(
		fixture.Random,
		fixture.RequireSuccess,
		calls,
		mustBigInt(t, fixture.MinGasLimit),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, makeNativeRelayAdaptActionData(actionData), fixture.ActionData)

	params, err := RelayAdaptParamsFromNullifiers(
		fixture.Nullifiers,
		fixture.Random,
		fixture.RequireSuccess,
		calls,
		mustBigInt(t, fixture.MinGasLimit),
	)
	if err != nil {
		t.Fatal(err)
	}
	if params != fixture.RelayAdaptParams {
		t.Fatalf("expected relay adapt params %s, got %s", fixture.RelayAdaptParams, params)
	}
	if _, err := FormatRelayAdaptRandom("00"); err == nil {
		t.Fatal("expected invalid relay adapt random length to fail")
	}
}

func TestRelayAdaptCrossContractPolicyMatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).RelayAdaptFixtures.CrossContractPolicy
	if got := MinimumGasLimitForRelayAdaptContract(mustBigInt(t, fixture.MinimumGasLimit)).String(); got != fixture.MinGasLimitForContract {
		t.Fatalf("expected min gas limit for contract %s, got %s", fixture.MinGasLimitForContract, got)
	}
	if got := MinimumGasLimitForRelayAdaptContract(nil).String(); got != fixture.MinGasLimitForContract {
		t.Fatalf("expected default min gas limit for contract %s, got %s", fixture.MinGasLimitForContract, got)
	}
	for _, test := range fixture.RequireSuccess {
		got := ShouldRequireSuccessForCrossContractCalls(test.IsGasEstimate, test.IsBroadcasterTransaction)
		if got != test.Output {
			t.Fatalf("expected requireSuccess=%t for %+v, got %t", test.Output, test, got)
		}
	}
}

func TestGenerateRelayShieldRequestsMatchesTypeScript(t *testing.T) {
	fixture := loadExportedFixtures(t).RelayAdaptFixtures.ShieldRequests
	requests, err := GenerateRelayShieldRequestsWithRandomness(
		fixture.Random,
		fixture.ERC20Recipients,
		fixture.NFTRecipients,
		fixture.Randomness,
	)
	if err != nil {
		t.Fatal(err)
	}
	native := make([]NativeShieldRequest, len(requests))
	for i, request := range requests {
		native[i] = request.Native()
	}
	assertJSONEqual(t, native, fixture.Requests)

	if _, err := GenerateRelayShieldRequestsWithRandomness(
		fixture.Random,
		fixture.ERC20Recipients,
		fixture.NFTRecipients,
		fixture.Randomness[:1],
	); err == nil {
		t.Fatal("expected short relay shield randomness to fail")
	}

	badNFTRecipients := append([]RelayShieldNFTRecipient(nil), fixture.NFTRecipients...)
	badNFTRecipients[0].NFTTokenData.TokenType = railcrypto.TokenTypeERC20
	if _, err := GenerateRelayShieldRequestsWithRandomness(
		fixture.Random,
		nil,
		badNFTRecipients,
		fixture.Randomness[:len(badNFTRecipients)],
	); err == nil {
		t.Fatal("expected unsupported relay shield NFT token type to fail")
	}
}

func TestRelayAdaptCalldataMatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t).RelayAdaptFixtures
	calldataFixture := fixtures.Calldata
	calls := mustRelayAdaptCalls(t, fixtures.Params.Calls)
	actionData, err := NewRelayAdaptActionData(
		fixtures.Params.Random,
		fixtures.Params.RequireSuccess,
		calls,
		mustBigInt(t, fixtures.Params.MinGasLimit),
	)
	if err != nil {
		t.Fatal(err)
	}
	requests := make([]ShieldRequest, len(fixtures.ShieldRequests.Requests))
	for i, request := range fixtures.ShieldRequests.Requests {
		requests[i] = mustShieldRequest(t, request)
	}

	relayCalldata, err := EncodeRelayAdaptV2Calldata(nil, actionData)
	if err != nil {
		t.Fatal(err)
	}
	if relayCalldata != calldataFixture.Relay {
		t.Fatalf("expected relay calldata %s, got %s", calldataFixture.Relay, relayCalldata)
	}
	multicallCalldata, err := EncodeRelayAdaptMulticallCalldata(true, calls)
	if err != nil {
		t.Fatal(err)
	}
	if multicallCalldata != calldataFixture.Multicall {
		t.Fatalf("expected multicall calldata %s, got %s", calldataFixture.Multicall, multicallCalldata)
	}
	shieldCalldata, err := EncodeRelayAdaptShieldCalldata(requests)
	if err != nil {
		t.Fatal(err)
	}
	if shieldCalldata != calldataFixture.Shield {
		t.Fatalf("expected shield calldata %s, got %s", calldataFixture.Shield, shieldCalldata)
	}

	baseToken, err := railcrypto.TokenDataERC20(zeroAddress)
	if err != nil {
		t.Fatal(err)
	}
	baseTransfer, err := NewRelayAdaptTokenTransfer(baseToken, calldataFixture.UnshieldAddress, big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
	transferCalldata, err := EncodeRelayAdaptTransferCalldata([]RelayAdaptTokenTransfer{baseTransfer})
	if err != nil {
		t.Fatal(err)
	}
	if transferCalldata != calldataFixture.Transfer {
		t.Fatalf("expected transfer calldata %s, got %s", calldataFixture.Transfer, transferCalldata)
	}
	wrapBaseCalldata, err := EncodeRelayAdaptWrapBaseCalldata(mustBigInt(t, calldataFixture.WrapBaseAmount))
	if err != nil {
		t.Fatal(err)
	}
	if wrapBaseCalldata != calldataFixture.WrapBase {
		t.Fatalf("expected wrapBase calldata %s, got %s", calldataFixture.WrapBase, wrapBaseCalldata)
	}
	unwrapBaseCalldata, err := EncodeRelayAdaptUnwrapBaseCalldata(mustBigInt(t, calldataFixture.UnwrapBaseAmount))
	if err != nil {
		t.Fatal(err)
	}
	if unwrapBaseCalldata != calldataFixture.UnwrapBase {
		t.Fatalf("expected unwrapBase calldata %s, got %s", calldataFixture.UnwrapBase, unwrapBaseCalldata)
	}

	unshieldCalls, err := RelayAdaptOrderedCallsForUnshieldBaseToken(calldataFixture.RelayAdaptAddress, calldataFixture.UnshieldAddress)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, makeNativeRelayAdaptCalls(unshieldCalls), calldataFixture.UnshieldBaseCalls)
	txs := transactionsWithNullifiers(fixtures.Params.Nullifiers)
	unshieldParams, err := RelayAdaptParamsUnshieldBaseTokenV2(
		txs,
		calldataFixture.RelayAdaptAddress,
		calldataFixture.UnshieldAddress,
		fixtures.Params.Random,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if unshieldParams != calldataFixture.UnshieldBaseParams {
		t.Fatalf("expected unshield base params %s, got %s", calldataFixture.UnshieldBaseParams, unshieldParams)
	}

	crossContractCalls, err := RelayAdaptOrderedCallsForCrossContractCalls(calldataFixture.RelayAdaptAddress, calls, requests)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, makeNativeRelayAdaptCalls(crossContractCalls), calldataFixture.CrossContractCallsWithShield)
	crossContractParams, err := RelayAdaptParamsCrossContractCallsV2(
		txs,
		calldataFixture.RelayAdaptAddress,
		calls,
		requests,
		fixtures.Params.Random,
		true,
		mustBigInt(t, calldataFixture.CrossContractMinGasLimit),
	)
	if err != nil {
		t.Fatal(err)
	}
	if crossContractParams != calldataFixture.CrossContractParams {
		t.Fatalf("expected cross contract params %s, got %s", calldataFixture.CrossContractParams, crossContractParams)
	}
	if calldataFixture.CrossContractRequireSuccess {
		t.Fatal("expected broadcaster cross-contract params to allow call failure")
	}

	baseShieldRequest := mustShieldRequest(t, calldataFixture.BaseShieldRequest)
	populatedShieldBase, err := RelayAdaptPopulateShieldBaseToken(calldataFixture.RelayAdaptAddress, baseShieldRequest)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, makeNativeRelayAdaptTransactionRequest(populatedShieldBase), calldataFixture.PopulatedShieldBaseToken)
	populatedMulticall, err := RelayAdaptPopulateMulticall(calldataFixture.RelayAdaptAddress, calls, requests)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, makeNativeRelayAdaptTransactionRequest(populatedMulticall), calldataFixture.PopulatedMulticall)
	populatedUnshieldBase, err := RelayAdaptPopulateUnshieldBaseTokenV2(
		nil,
		calldataFixture.RelayAdaptAddress,
		calldataFixture.UnshieldAddress,
		fixtures.Params.Random,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, makeNativeRelayAdaptTransactionRequest(populatedUnshieldBase), calldataFixture.PopulatedUnshieldBaseToken)
	populatedCrossContract, err := RelayAdaptPopulateCrossContractCallsV2(
		nil,
		calldataFixture.RelayAdaptAddress,
		calls,
		requests,
		fixtures.Params.Random,
		false,
		true,
		mustBigInt(t, calldataFixture.CrossContractMinGasLimit),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, makeNativeRelayAdaptTransactionRequest(populatedCrossContract), calldataFixture.PopulatedCrossContract)
}

func TestParseRelayAdaptReturnValueMatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t).RelayAdaptFixtures
	for _, fixture := range fixtures.ParseReturnValues {
		t.Run(fixture.Name, func(t *testing.T) {
			parsed := ParseRelayAdaptReturnValue(fixture.Data)
			got := nativeRelayAdaptParsedReturn{
				Error: parsed.Error,
			}
			if parsed.CallIndex != nil {
				got.CallIndex = strconv.FormatUint(*parsed.CallIndex, 10)
			}
			assertJSONEqual(t, got, fixture.Parsed)
		})
	}
}

func TestExtractGasEstimateCallFailedIndexAndErrorTextMatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t).RelayAdaptFixtures
	for _, fixture := range fixtures.GasEstimateErrors {
		t.Run(fixture.Name, func(t *testing.T) {
			parsed := ExtractGasEstimateCallFailedIndexAndErrorText(fixture.Input)
			assertJSONEqual(t, parsed, fixture.Parsed)
		})
	}
}

func TestGetRelayAdaptCallErrorMatchesTypeScript(t *testing.T) {
	fixtures := loadExportedFixtures(t).RelayAdaptFixtures
	if RelayAdaptCallErrorTopic() != fixtures.CallErrorTopic {
		t.Fatalf("expected call error topic %s, got %s", fixtures.CallErrorTopic, RelayAdaptCallErrorTopic())
	}
	for _, fixture := range fixtures.CallErrorLogs {
		t.Run(fixture.Name, func(t *testing.T) {
			got, ok, err := GetRelayAdaptCallError(fixture.Logs)
			if err != nil {
				t.Fatal(err)
			}
			if fixture.Parsed == nil {
				if ok {
					t.Fatalf("expected no parsed error, got %q", got)
				}
				return
			}
			if !ok {
				t.Fatalf("expected parsed error %q, got none", *fixture.Parsed)
			}
			if got != *fixture.Parsed {
				t.Fatalf("expected parsed error %q, got %q", *fixture.Parsed, got)
			}
		})
	}
}

type relayAdaptFixtureSet struct {
	Params              relayAdaptParamsFixture         `json:"params"`
	ShieldRequests      relayAdaptShieldRequestsFixture `json:"shieldRequests"`
	Calldata            relayAdaptCalldataFixture       `json:"calldata"`
	CrossContractPolicy relayAdaptPolicyFixture         `json:"crossContractPolicy"`
	ParseReturnValues   []relayAdaptParseReturnFixture  `json:"parseReturnValues"`
	GasEstimateErrors   []relayAdaptGasErrorFixture     `json:"gasEstimateErrors"`
	CallErrorTopic      string                          `json:"callErrorTopic"`
	CallErrorLogs       []relayAdaptCallErrorFixture    `json:"callErrorLogs"`
}

type relayAdaptParamsFixture struct {
	Nullifiers       [][]string                 `json:"nullifiers"`
	Random           string                     `json:"random"`
	RequireSuccess   bool                       `json:"requireSuccess"`
	MinGasLimit      string                     `json:"minGasLimit"`
	Calls            []nativeRelayAdaptCall     `json:"calls"`
	ActionData       nativeRelayAdaptActionData `json:"actionData"`
	RelayAdaptParams string                     `json:"relayAdaptParams"`
}

type relayAdaptShieldRequestsFixture struct {
	Random          string                         `json:"random"`
	ERC20Recipients []RelayShieldERC20Recipient    `json:"erc20Recipients"`
	NFTRecipients   []RelayShieldNFTRecipient      `json:"nftRecipients"`
	Randomness      []RelayShieldRequestRandomness `json:"randomness"`
	Requests        []NativeShieldRequest          `json:"requests"`
}

type relayAdaptCalldataFixture struct {
	RelayAdaptAddress                   string                             `json:"relayAdaptAddress"`
	UnshieldAddress                     string                             `json:"unshieldAddress"`
	Relay                               string                             `json:"relay"`
	Multicall                           string                             `json:"multicall"`
	Shield                              string                             `json:"shield"`
	Transfer                            string                             `json:"transfer"`
	WrapBaseAmount                      string                             `json:"wrapBaseAmount"`
	WrapBase                            string                             `json:"wrapBase"`
	UnwrapBaseAmount                    string                             `json:"unwrapBaseAmount"`
	UnwrapBase                          string                             `json:"unwrapBase"`
	UnshieldBaseCalls                   []nativeRelayAdaptCall             `json:"unshieldBaseCalls"`
	UnshieldBaseParams                  string                             `json:"unshieldBaseParams"`
	CrossContractCallsWithShield        []nativeRelayAdaptCall             `json:"crossContractCallsWithShield"`
	CrossContractMinGasLimit            string                             `json:"crossContractMinGasLimit"`
	CrossContractMinGasLimitForContract string                             `json:"crossContractMinGasLimitForContract"`
	CrossContractRequireSuccess         bool                               `json:"crossContractRequireSuccess"`
	CrossContractParams                 string                             `json:"crossContractParams"`
	BaseShieldRequest                   NativeShieldRequest                `json:"baseShieldRequest"`
	PopulatedShieldBaseToken            nativeRelayAdaptTransactionRequest `json:"populatedShieldBaseToken"`
	PopulatedMulticall                  nativeRelayAdaptTransactionRequest `json:"populatedMulticall"`
	PopulatedUnshieldBaseToken          nativeRelayAdaptTransactionRequest `json:"populatedUnshieldBaseToken"`
	PopulatedCrossContract              nativeRelayAdaptTransactionRequest `json:"populatedCrossContract"`
}

type nativeRelayAdaptActionData struct {
	Random         string                 `json:"random"`
	RequireSuccess bool                   `json:"requireSuccess"`
	MinGasLimit    string                 `json:"minGasLimit"`
	Calls          []nativeRelayAdaptCall `json:"calls"`
}

type nativeRelayAdaptCall struct {
	To    string `json:"to"`
	Data  string `json:"data"`
	Value string `json:"value"`
}

type nativeRelayAdaptTransactionRequest struct {
	To       string `json:"to"`
	Data     string `json:"data"`
	Value    string `json:"value"`
	GasLimit string `json:"gasLimit,omitempty"`
}

type relayAdaptPolicyFixture struct {
	MinimumGasLimit        string                            `json:"minimumGasLimit"`
	MinGasLimitForContract string                            `json:"minGasLimitForContract"`
	RequireSuccess         []relayAdaptRequireSuccessFixture `json:"requireSuccess"`
}

type relayAdaptRequireSuccessFixture struct {
	IsGasEstimate            bool `json:"isGasEstimate"`
	IsBroadcasterTransaction bool `json:"isBroadcasterTransaction"`
	Output                   bool `json:"output"`
}

type relayAdaptParseReturnFixture struct {
	Name   string                       `json:"name"`
	Data   string                       `json:"data"`
	Parsed nativeRelayAdaptParsedReturn `json:"parsed"`
}

type relayAdaptGasErrorFixture struct {
	Name   string                     `json:"name"`
	Input  string                     `json:"input"`
	Parsed RelayAdaptGasEstimateError `json:"parsed"`
}

type relayAdaptCallErrorFixture struct {
	Name   string                 `json:"name"`
	Logs   []RelayAdaptReceiptLog `json:"logs"`
	Parsed *string                `json:"parsed"`
}

type nativeRelayAdaptParsedReturn struct {
	CallIndex string `json:"callIndex,omitempty"`
	Error     string `json:"error"`
}

func makeNativeRelayAdaptActionData(actionData RelayAdaptActionData) nativeRelayAdaptActionData {
	return nativeRelayAdaptActionData{
		Random:         railcrypto.BytesToHex(actionData.Random[:], false),
		RequireSuccess: actionData.RequireSuccess,
		MinGasLimit:    defaultBigIntForTest(actionData.MinGasLimit).String(),
		Calls:          makeNativeRelayAdaptCalls(actionData.Calls),
	}
}

func mustRelayAdaptCalls(t *testing.T, raw []nativeRelayAdaptCall) []RelayAdaptCall {
	t.Helper()
	calls := make([]RelayAdaptCall, len(raw))
	for i, call := range raw {
		relayCall, err := NewRelayAdaptCall(call.To, call.Data, mustBigInt(t, call.Value))
		if err != nil {
			t.Fatal(err)
		}
		calls[i] = relayCall
	}
	return calls
}

func makeNativeRelayAdaptCalls(calls []RelayAdaptCall) []nativeRelayAdaptCall {
	native := make([]nativeRelayAdaptCall, len(calls))
	for i, call := range calls {
		value := "0"
		if call.Value != nil {
			value = call.Value.String()
		}
		native[i] = nativeRelayAdaptCall{
			To:    call.To.Hex(),
			Data:  railcrypto.BytesToHex(call.Data, true),
			Value: value,
		}
	}
	return native
}

func makeNativeRelayAdaptTransactionRequest(request RelayAdaptTransactionRequest) nativeRelayAdaptTransactionRequest {
	native := nativeRelayAdaptTransactionRequest{
		To:    request.To,
		Data:  request.Data,
		Value: defaultBigIntForTest(request.Value).String(),
	}
	if request.GasLimit != nil {
		native.GasLimit = request.GasLimit.String()
	}
	return native
}

func transactionsWithNullifiers(nullifierGroups [][]string) []TransactionStructV2 {
	txs := make([]TransactionStructV2, len(nullifierGroups))
	for i, nullifiers := range nullifierGroups {
		txs[i] = TransactionStructV2{
			Nullifiers: append([]string(nil), nullifiers...),
		}
	}
	return txs
}

func defaultBigIntForTest(value *big.Int) *big.Int {
	if value == nil {
		return big.NewInt(0)
	}
	return value
}
