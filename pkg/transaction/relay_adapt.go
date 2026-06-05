package transaction

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/accounts/abi"

	"github.com/bf30075/railgun-go/pkg/address"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

const (
	ReturnDataRelayAdaptStringPrefix              = "0x5c0dee5d"
	ReturnDataStringPrefix                        = "0x08c379a0"
	MinimumRelayAdaptCrossContractCallsGasLimitV2 = 3_200_000
	RelayAdaptCallErrorEventSignature             = "CallError(uint256,bytes)"
)

type RelayAdaptReturnValue struct {
	CallIndex *uint64 `json:"callIndex,omitempty"`
	Error     string  `json:"error"`
}

type RelayAdaptGasEstimateError struct {
	CallFailedIndexString string `json:"callFailedIndexString"`
	ErrorMessage          string `json:"errorMessage"`
}

type RelayAdaptReceiptLog struct {
	Topics []string `json:"topics"`
	Data   string   `json:"data"`
}

type RelayAdaptTransactionRequest struct {
	To       string
	Data     string
	Value    *big.Int
	GasLimit *big.Int
}

type RelayShieldERC20Recipient struct {
	TokenAddress     string `json:"tokenAddress"`
	RecipientAddress string `json:"recipientAddress"`
}

type RelayShieldNFTRecipient struct {
	NFTTokenData     railcrypto.TokenData `json:"nftTokenData"`
	RecipientAddress string               `json:"recipientAddress"`
}

type RelayShieldRequestRandomness struct {
	ShieldPrivateKey string `json:"shieldPrivateKey"`
	RandomGCMIV      string `json:"randomGCMIV"`
	ReceiverCTRIV    string `json:"receiverCTRIV"`
}

func ShouldRequireSuccessForCrossContractCalls(isGasEstimate bool, isBroadcasterTransaction bool) bool {
	return !(isBroadcasterTransaction && !isGasEstimate)
}

func MinimumGasLimitForRelayAdaptContract(minimumGasLimit *big.Int) *big.Int {
	if minimumGasLimit == nil {
		minimumGasLimit = big.NewInt(MinimumRelayAdaptCrossContractCallsGasLimitV2)
	}
	return new(big.Int).Sub(minimumGasLimit, big.NewInt(150_000))
}

func FormatRelayAdaptRandom(random string) ([31]byte, error) {
	stripped := railcrypto.Strip0x(random)
	if len(stripped) != 62 {
		return [31]byte{}, fmt.Errorf("Relay Adapt random parameter must be a hex string of length 62 (31 bytes).")
	}
	decoded, err := hex.DecodeString(stripped)
	if err != nil {
		return [31]byte{}, err
	}
	var out [31]byte
	copy(out[:], decoded)
	return out, nil
}

func NewRelayAdaptCall(to string, data string, value *big.Int) (RelayAdaptCall, error) {
	address, err := AddressFromHex(to)
	if err != nil {
		return RelayAdaptCall{}, err
	}
	callData, err := railcrypto.HexToBytes(data)
	if err != nil {
		return RelayAdaptCall{}, err
	}
	if value == nil {
		value = big.NewInt(0)
	}
	return RelayAdaptCall{
		To:    address,
		Data:  callData,
		Value: new(big.Int).Set(value),
	}, nil
}

func NewRelayAdaptTokenTransfer(token railcrypto.TokenData, to string, value *big.Int) (RelayAdaptTokenTransfer, error) {
	address, err := AddressFromHex(to)
	if err != nil {
		return RelayAdaptTokenTransfer{}, err
	}
	if value == nil {
		value = big.NewInt(0)
	}
	return RelayAdaptTokenTransfer{
		Token: token,
		To:    address,
		Value: new(big.Int).Set(value),
	}, nil
}

func NewRelayAdaptActionData(random string, requireSuccess bool, calls []RelayAdaptCall, minGasLimit *big.Int) (RelayAdaptActionData, error) {
	formattedRandom, err := FormatRelayAdaptRandom(random)
	if err != nil {
		return RelayAdaptActionData{}, err
	}
	if minGasLimit == nil {
		minGasLimit = big.NewInt(0)
	}
	return RelayAdaptActionData{
		Random:         formattedRandom,
		RequireSuccess: requireSuccess,
		MinGasLimit:    new(big.Int).Set(minGasLimit),
		Calls:          cloneRelayAdaptCalls(calls),
	}, nil
}

func RelayAdaptWrapBaseCall(relayAdaptAddress string, amount *big.Int) (RelayAdaptCall, error) {
	data, err := EncodeRelayAdaptWrapBaseCalldata(amount)
	if err != nil {
		return RelayAdaptCall{}, err
	}
	return NewRelayAdaptCall(relayAdaptAddress, data, nil)
}

func RelayAdaptUnwrapBaseCall(relayAdaptAddress string, amount *big.Int) (RelayAdaptCall, error) {
	data, err := EncodeRelayAdaptUnwrapBaseCalldata(amount)
	if err != nil {
		return RelayAdaptCall{}, err
	}
	return NewRelayAdaptCall(relayAdaptAddress, data, nil)
}

func RelayAdaptTransferCall(relayAdaptAddress string, transfers []RelayAdaptTokenTransfer) (RelayAdaptCall, error) {
	data, err := EncodeRelayAdaptTransferCalldata(transfers)
	if err != nil {
		return RelayAdaptCall{}, err
	}
	return NewRelayAdaptCall(relayAdaptAddress, data, nil)
}

func RelayAdaptShieldCall(relayAdaptAddress string, shieldRequests []ShieldRequest) (RelayAdaptCall, error) {
	data, err := EncodeRelayAdaptShieldCalldata(shieldRequests)
	if err != nil {
		return RelayAdaptCall{}, err
	}
	return NewRelayAdaptCall(relayAdaptAddress, data, nil)
}

func RelayAdaptPopulateShieldBaseToken(relayAdaptAddress string, shieldRequest ShieldRequest) (RelayAdaptTransactionRequest, error) {
	wrapCall, err := RelayAdaptWrapBaseCall(relayAdaptAddress, shieldRequest.Preimage.Value)
	if err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	shieldCall, err := RelayAdaptShieldCall(relayAdaptAddress, []ShieldRequest{shieldRequest})
	if err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	data, err := EncodeRelayAdaptMulticallCalldata(true, []RelayAdaptCall{wrapCall, shieldCall})
	if err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	return newRelayAdaptTransactionRequest(relayAdaptAddress, data, shieldRequest.Preimage.Value, nil)
}

func RelayAdaptPopulateMulticall(relayAdaptAddress string, calls []RelayAdaptCall, shieldRequests []ShieldRequest) (RelayAdaptTransactionRequest, error) {
	orderedCalls, err := RelayAdaptOrderedCallsForCrossContractCalls(relayAdaptAddress, calls, shieldRequests)
	if err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	data, err := EncodeRelayAdaptMulticallCalldata(true, orderedCalls)
	if err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	return newRelayAdaptTransactionRequest(relayAdaptAddress, data, nil, nil)
}

func RelayAdaptPopulateRelayV2(relayAdaptAddress string, transactions []TransactionStructV2, random string, requireSuccess bool, calls []RelayAdaptCall, minGasLimit *big.Int, gasLimit *big.Int) (RelayAdaptTransactionRequest, error) {
	actionData, err := NewRelayAdaptActionData(random, requireSuccess, calls, minGasLimit)
	if err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	data, err := EncodeRelayAdaptV2Calldata(transactions, actionData)
	if err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	return newRelayAdaptTransactionRequest(relayAdaptAddress, data, nil, gasLimit)
}

func RelayAdaptPopulateUnshieldBaseTokenV2(transactions []TransactionStructV2, relayAdaptAddress string, unshieldAddress string, random string, sendWithPublicWallet bool) (RelayAdaptTransactionRequest, error) {
	orderedCalls, err := RelayAdaptOrderedCallsForUnshieldBaseToken(relayAdaptAddress, unshieldAddress)
	if err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	return RelayAdaptPopulateRelayV2(relayAdaptAddress, transactions, random, sendWithPublicWallet, orderedCalls, nil, nil)
}

func RelayAdaptPopulateCrossContractCallsV2(transactions []TransactionStructV2, relayAdaptAddress string, crossContractCalls []RelayAdaptCall, relayShieldRequests []ShieldRequest, random string, isGasEstimate bool, isBroadcasterTransaction bool, minGasLimit *big.Int) (RelayAdaptTransactionRequest, error) {
	orderedCalls, err := RelayAdaptOrderedCallsForCrossContractCalls(relayAdaptAddress, crossContractCalls, relayShieldRequests)
	if err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	if minGasLimit == nil {
		minGasLimit = big.NewInt(MinimumRelayAdaptCrossContractCallsGasLimitV2)
	}
	requireSuccess := ShouldRequireSuccessForCrossContractCalls(isGasEstimate, isBroadcasterTransaction)
	return RelayAdaptPopulateRelayV2(
		relayAdaptAddress,
		transactions,
		random,
		requireSuccess,
		orderedCalls,
		MinimumGasLimitForRelayAdaptContract(minGasLimit),
		minGasLimit,
	)
}

func RelayAdaptOrderedCallsForUnshieldBaseToken(relayAdaptAddress string, unshieldAddress string) ([]RelayAdaptCall, error) {
	baseTokenData, err := railcrypto.TokenDataERC20(zeroAddress)
	if err != nil {
		return nil, err
	}
	baseTransfer, err := NewRelayAdaptTokenTransfer(baseTokenData, unshieldAddress, big.NewInt(0))
	if err != nil {
		return nil, err
	}
	unwrapCall, err := RelayAdaptUnwrapBaseCall(relayAdaptAddress, big.NewInt(0))
	if err != nil {
		return nil, err
	}
	transferCall, err := RelayAdaptTransferCall(relayAdaptAddress, []RelayAdaptTokenTransfer{baseTransfer})
	if err != nil {
		return nil, err
	}
	return []RelayAdaptCall{unwrapCall, transferCall}, nil
}

func RelayAdaptOrderedCallsForCrossContractCalls(relayAdaptAddress string, crossContractCalls []RelayAdaptCall, relayShieldRequests []ShieldRequest) ([]RelayAdaptCall, error) {
	orderedCalls := cloneRelayAdaptCalls(crossContractCalls)
	if len(relayShieldRequests) == 0 {
		return orderedCalls, nil
	}
	shieldCall, err := RelayAdaptShieldCall(relayAdaptAddress, relayShieldRequests)
	if err != nil {
		return nil, err
	}
	return append(orderedCalls, shieldCall), nil
}

func RelayAdaptParamsUnshieldBaseTokenV2(transactions []TransactionStructV2, relayAdaptAddress string, unshieldAddress string, random string, sendWithPublicWallet bool) (string, error) {
	orderedCalls, err := RelayAdaptOrderedCallsForUnshieldBaseToken(relayAdaptAddress, unshieldAddress)
	if err != nil {
		return "", err
	}
	return RelayAdaptParamsFromTransactionsV2(transactions, random, sendWithPublicWallet, orderedCalls, nil)
}

func RelayAdaptParamsCrossContractCallsV2(transactions []TransactionStructV2, relayAdaptAddress string, crossContractCalls []RelayAdaptCall, relayShieldRequests []ShieldRequest, random string, isBroadcasterTransaction bool, minGasLimit *big.Int) (string, error) {
	orderedCalls, err := RelayAdaptOrderedCallsForCrossContractCalls(relayAdaptAddress, crossContractCalls, relayShieldRequests)
	if err != nil {
		return "", err
	}
	if minGasLimit == nil {
		minGasLimit = big.NewInt(MinimumRelayAdaptCrossContractCallsGasLimitV2)
	}
	requireSuccess := ShouldRequireSuccessForCrossContractCalls(false, isBroadcasterTransaction)
	return RelayAdaptParamsFromTransactionsV2(
		transactions,
		random,
		requireSuccess,
		orderedCalls,
		MinimumGasLimitForRelayAdaptContract(minGasLimit),
	)
}

func RelayAdaptParamsFromTransactionsV2(transactions []TransactionStructV2, random string, requireSuccess bool, calls []RelayAdaptCall, minGasLimit *big.Int) (string, error) {
	nullifiers := make([][]string, len(transactions))
	for i, transaction := range transactions {
		nullifiers[i] = transaction.Nullifiers
	}
	return RelayAdaptParamsFromNullifiers(nullifiers, random, requireSuccess, calls, minGasLimit)
}

func RelayAdaptParamsFromTransactionsV3(transactions []TransactionStructV3, random string, requireSuccess bool, calls []RelayAdaptCall, minGasLimit *big.Int) (string, error) {
	nullifiers := make([][]string, len(transactions))
	for i, transaction := range transactions {
		nullifiers[i] = transaction.Nullifiers
	}
	return RelayAdaptParamsFromNullifiers(nullifiers, random, requireSuccess, calls, minGasLimit)
}

func RelayAdaptParamsFromNullifiers(nullifierGroups [][]string, random string, requireSuccess bool, calls []RelayAdaptCall, minGasLimit *big.Int) (string, error) {
	nullifiers := make([][][32]byte, len(nullifierGroups))
	for i, group := range nullifierGroups {
		nullifiers[i] = make([][32]byte, len(group))
		for j, nullifier := range group {
			value, err := Bytes32FromHex(nullifier)
			if err != nil {
				return "", fmt.Errorf("nullifiers[%d][%d]: %w", i, j, err)
			}
			nullifiers[i][j] = value
		}
	}
	actionData, err := NewRelayAdaptActionData(random, requireSuccess, calls, minGasLimit)
	if err != nil {
		return "", err
	}
	packed, err := packRelayAdaptParams(nullifiers, actionData)
	if err != nil {
		return "", err
	}
	return "0x" + railcrypto.Keccak256HexBytes(packed), nil
}

func GenerateRelayShieldRequests(random string, erc20Recipients []RelayShieldERC20Recipient, nftRecipients []RelayShieldNFTRecipient) ([]ShieldRequest, error) {
	return GenerateRelayShieldRequestsWithRandomness(random, erc20Recipients, nftRecipients, nil)
}

func GenerateRelayShieldRequestsWithRandomness(random string, erc20Recipients []RelayShieldERC20Recipient, nftRecipients []RelayShieldNFTRecipient, randomness []RelayShieldRequestRandomness) ([]ShieldRequest, error) {
	totalRequests := len(erc20Recipients) + len(nftRecipients)
	useProvidedRandomness := randomness != nil
	if useProvidedRandomness && len(randomness) != totalRequests {
		return nil, fmt.Errorf("expected %d relay shield randomness entries, got %d", totalRequests, len(randomness))
	}

	requests := make([]ShieldRequest, 0, totalRequests)
	randomnessIndex := 0
	for i, recipient := range erc20Recipients {
		tokenData, err := railcrypto.TokenDataERC20(recipient.TokenAddress)
		if err != nil {
			return nil, fmt.Errorf("erc20 recipient[%d] token: %w", i, err)
		}
		request, err := createRelayShieldRequest(random, recipient.RecipientAddress, big.NewInt(0), tokenData, relayShieldRandomnessAt(randomness, randomnessIndex, useProvidedRandomness))
		if err != nil {
			return nil, fmt.Errorf("erc20 recipient[%d]: %w", i, err)
		}
		requests = append(requests, request)
		randomnessIndex++
	}
	for i, recipient := range nftRecipients {
		value, err := relayShieldNFTValue(recipient.NFTTokenData)
		if err != nil {
			return nil, fmt.Errorf("nft recipient[%d]: %w", i, err)
		}
		request, err := createRelayShieldRequest(random, recipient.RecipientAddress, value, recipient.NFTTokenData, relayShieldRandomnessAt(randomness, randomnessIndex, useProvidedRandomness))
		if err != nil {
			return nil, fmt.Errorf("nft recipient[%d]: %w", i, err)
		}
		requests = append(requests, request)
		randomnessIndex++
	}
	return requests, nil
}

func ParseRelayAdaptReturnValue(returnValue string) RelayAdaptReturnValue {
	if strings.Contains(returnValue, ReturnDataRelayAdaptStringPrefix) {
		stripped := strings.Replace(returnValue, ReturnDataRelayAdaptStringPrefix, "0x", 1)
		parsed, err := customRelayAdaptErrorParse(stripped)
		if err != nil {
			return RelayAdaptReturnValue{Error: unknownRelayAdaptError(err)}
		}
		return parsed
	}
	if strings.Contains(returnValue, ReturnDataStringPrefix) {
		return RelayAdaptReturnValue{Error: parseRelayAdaptStringError(returnValue)}
	}
	return RelayAdaptReturnValue{
		Error: fmt.Sprintf(
			"Not a RelayAdapt return value: must be prefixed with %s or %s",
			ReturnDataRelayAdaptStringPrefix,
			ReturnDataStringPrefix,
		),
	}
}

func ExtractGasEstimateCallFailedIndexAndErrorText(errorMessage string) RelayAdaptGasEstimateError {
	prefixSplit := ` (action="estimateGas", data="`
	splitResult := strings.Split(errorMessage, prefixSplit)
	if len(splitResult) < 2 {
		return RelayAdaptGasEstimateError{
			CallFailedIndexString: "UNKNOWN",
			ErrorMessage:          errorMessage,
		}
	}
	dataParts := strings.Split(splitResult[1], `"`)
	if len(dataParts) == 0 {
		return RelayAdaptGasEstimateError{
			CallFailedIndexString: "UNKNOWN",
			ErrorMessage:          errorMessage,
		}
	}
	parsed := ParseRelayAdaptReturnValue(dataParts[0])
	callIndex := "UNKNOWN"
	if parsed.CallIndex != nil {
		callIndex = fmt.Sprintf("%d", *parsed.CallIndex)
	}
	return RelayAdaptGasEstimateError{
		CallFailedIndexString: callIndex,
		ErrorMessage:          fmt.Sprintf("'%s': %s", splitResult[0], parsed.Error),
	}
}

func RelayAdaptCallErrorTopic() string {
	return "0x" + railcrypto.Keccak256HexBytes([]byte(RelayAdaptCallErrorEventSignature))
}

func GetRelayAdaptCallError(receiptLogs []RelayAdaptReceiptLog) (string, bool, error) {
	topic := RelayAdaptCallErrorTopic()
	for i, log := range receiptLogs {
		if len(log.Topics) == 0 || !strings.EqualFold(log.Topics[0], topic) {
			continue
		}
		parsed, err := customRelayAdaptErrorParse(log.Data)
		if err != nil {
			return "", false, fmt.Errorf("log[%d]: %w", i, err)
		}
		return parsed.Error, true, nil
	}
	return "", false, nil
}

func createRelayShieldRequest(random string, recipientAddress string, value *big.Int, tokenData railcrypto.TokenData, randomness *RelayShieldRequestRandomness) (ShieldRequest, error) {
	recipient, err := address.Decode(recipientAddress)
	if err != nil {
		return ShieldRequest{}, fmt.Errorf("recipient address: %w", err)
	}
	masterPublicKey, err := railcrypto.NumberishToBigInt(recipient.MasterPublicKey)
	if err != nil {
		return ShieldRequest{}, fmt.Errorf("recipient master public key: %w", err)
	}
	viewingPublicKey, err := railcrypto.HexToBytes(recipient.ViewingPublicKey)
	if err != nil {
		return ShieldRequest{}, fmt.Errorf("recipient viewing public key: %w", err)
	}
	shieldPrivateKey, randomGCMIV, receiverCTRIV, err := relayShieldEntropy(randomness)
	if err != nil {
		return ShieldRequest{}, err
	}
	return CreateShieldNoteRequest(ShieldNoteInputs{
		MasterPublicKey:          masterPublicKey,
		Random:                   random,
		Value:                    value,
		TokenData:                tokenData,
		ShieldPrivateKey:         shieldPrivateKey,
		ReceiverViewingPublicKey: viewingPublicKey,
		RandomGCMIV:              randomGCMIV,
		ReceiverCTRIV:            receiverCTRIV,
	})
}

func relayShieldNFTValue(tokenData railcrypto.TokenData) (*big.Int, error) {
	switch tokenData.TokenType {
	case railcrypto.TokenTypeERC721:
		return big.NewInt(1), nil
	case railcrypto.TokenTypeERC1155:
		return big.NewInt(0), nil
	default:
		return nil, fmt.Errorf("unhandled NFT token type %d", tokenData.TokenType)
	}
}

func relayShieldRandomnessAt(randomness []RelayShieldRequestRandomness, index int, useProvided bool) *RelayShieldRequestRandomness {
	if !useProvided {
		return nil
	}
	return &randomness[index]
}

func relayShieldEntropy(randomness *RelayShieldRequestRandomness) ([]byte, string, string, error) {
	if randomness == nil {
		shieldPrivateKey, err := randomBytes(32)
		if err != nil {
			return nil, "", "", err
		}
		randomGCMIV, err := randomHex(16)
		if err != nil {
			return nil, "", "", err
		}
		receiverCTRIV, err := randomHex(16)
		if err != nil {
			return nil, "", "", err
		}
		return shieldPrivateKey, randomGCMIV, receiverCTRIV, nil
	}
	shieldPrivateKey, err := railcrypto.HexToBytes(randomness.ShieldPrivateKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("shield private key: %w", err)
	}
	if len(shieldPrivateKey) != 32 {
		return nil, "", "", fmt.Errorf("shield private key must be 32 bytes")
	}
	randomGCMIV, err := relayShieldIV(randomness.RandomGCMIV, "random GCM IV")
	if err != nil {
		return nil, "", "", err
	}
	receiverCTRIV, err := relayShieldIV(randomness.ReceiverCTRIV, "receiver CTR IV")
	if err != nil {
		return nil, "", "", err
	}
	return shieldPrivateKey, randomGCMIV, receiverCTRIV, nil
}

func relayShieldIV(value string, name string) (string, error) {
	stripped := railcrypto.Strip0x(value)
	if len(stripped) != 32 {
		return "", fmt.Errorf("%s must be 16 bytes", name)
	}
	if _, err := hex.DecodeString(stripped); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return stripped, nil
}

func randomBytes(byteLength int) ([]byte, error) {
	out := make([]byte, byteLength)
	if _, err := cryptorand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func randomHex(byteLength int) (string, error) {
	bytes, err := randomBytes(byteLength)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(bytes, false), nil
}

func customRelayAdaptErrorParse(data string) (RelayAdaptReturnValue, error) {
	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return RelayAdaptReturnValue{}, err
	}
	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return RelayAdaptReturnValue{}, err
	}
	args := abi.Arguments{
		{Type: uint256Type},
		{Type: bytesType},
	}
	dataBytes, err := railcrypto.HexToBytes(data)
	if err != nil {
		return RelayAdaptReturnValue{}, err
	}
	decoded, err := args.Unpack(dataBytes)
	if err != nil {
		return RelayAdaptReturnValue{}, err
	}
	callIndexBig, ok := decoded[0].(*big.Int)
	if !ok || !callIndexBig.IsUint64() {
		return RelayAdaptReturnValue{}, fmt.Errorf("invalid call index")
	}
	revertReasonBytes, ok := decoded[1].([]byte)
	if !ok {
		return RelayAdaptReturnValue{}, fmt.Errorf("invalid revert reason")
	}
	callIndex := callIndexBig.Uint64()
	return RelayAdaptReturnValue{
		CallIndex: &callIndex,
		Error:     parseRelayAdaptStringError(railcrypto.BytesToHex(revertReasonBytes, true)),
	}, nil
}

func parseRelayAdaptStringError(revertReason string) string {
	if strings.Contains(revertReason, ReturnDataStringPrefix) {
		stripped := strings.Replace(revertReason, ReturnDataStringPrefix, "0x", 1)
		parsed, err := abiDecodeString(stripped)
		if err != nil {
			return unknownRelayAdaptError(err)
		}
		return parsed
	}
	revertReasonBytes, err := railcrypto.HexToBytes(revertReason)
	if err != nil {
		return unknownRelayAdaptError(err)
	}
	if len(revertReasonBytes) == 0 {
		return unknownRelayAdaptError(fmt.Errorf("No utf8 string parsed from revert reason."))
	}
	if !utf8.Valid(revertReasonBytes) {
		return unknownRelayAdaptError(fmt.Errorf("invalid codepoint at offset 0; bad codepoint prefix"))
	}
	return string(revertReasonBytes)
}

func abiDecodeString(data string) (string, error) {
	stringType, err := abi.NewType("string", "", nil)
	if err != nil {
		return "", err
	}
	args := abi.Arguments{{Type: stringType}}
	dataBytes, err := railcrypto.HexToBytes(data)
	if err != nil {
		return "", err
	}
	decoded, err := args.Unpack(dataBytes)
	if err != nil {
		return "", err
	}
	value, ok := decoded[0].(string)
	if !ok {
		return "", fmt.Errorf("invalid string")
	}
	return value, nil
}

func unknownRelayAdaptError(err error) string {
	return fmt.Sprintf("Unknown Relay Adapt error: %s", err)
}

func newRelayAdaptTransactionRequest(to string, data string, value *big.Int, gasLimit *big.Int) (RelayAdaptTransactionRequest, error) {
	address, err := AddressFromHex(to)
	if err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	if _, err := railcrypto.HexToBytes(data); err != nil {
		return RelayAdaptTransactionRequest{}, err
	}
	return RelayAdaptTransactionRequest{
		To:       address.Hex(),
		Data:     data,
		Value:    bigIntOrZero(value),
		GasLimit: cloneBigInt(gasLimit),
	}, nil
}

func packRelayAdaptParams(nullifiers [][][32]byte, actionData RelayAdaptActionData) ([]byte, error) {
	actionDataType, err := abi.NewType("tuple", "actionData", []abi.ArgumentMarshaling{
		{Name: "random", Type: "bytes31"},
		{Name: "requireSuccess", Type: "bool"},
		{Name: "minGasLimit", Type: "uint256"},
		{
			Name: "calls",
			Type: "tuple[]",
			Components: []abi.ArgumentMarshaling{
				{Name: "to", Type: "address"},
				{Name: "data", Type: "bytes"},
				{Name: "value", Type: "uint256"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	bytes32ArrayType, err := abi.NewType("bytes32[][]", "nullifiers", nil)
	if err != nil {
		return nil, err
	}
	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, err
	}
	return abi.Arguments{
		{Type: bytes32ArrayType},
		{Type: uint256Type},
		{Type: actionDataType},
	}.Pack(nullifiers, new(big.Int).SetUint64(uint64(len(nullifiers))), actionData)
}

func cloneRelayAdaptCalls(calls []RelayAdaptCall) []RelayAdaptCall {
	out := make([]RelayAdaptCall, len(calls))
	for i, call := range calls {
		out[i] = RelayAdaptCall{
			To:    call.To,
			Data:  append([]byte(nil), call.Data...),
			Value: cloneBigInt(call.Value),
		}
	}
	return out
}
