package transaction

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

const railgunSmartWalletTransactABI = `[
  {
    "type": "function",
    "name": "transact",
    "stateMutability": "payable",
    "outputs": [],
    "inputs": [
      {
        "name": "_transactions",
        "type": "tuple[]",
        "components": [
          {
            "name": "proof",
            "type": "tuple",
            "components": [
              {"name": "a", "type": "tuple", "components": [{"name": "x", "type": "uint256"}, {"name": "y", "type": "uint256"}]},
              {"name": "b", "type": "tuple", "components": [{"name": "x", "type": "uint256[2]"}, {"name": "y", "type": "uint256[2]"}]},
              {"name": "c", "type": "tuple", "components": [{"name": "x", "type": "uint256"}, {"name": "y", "type": "uint256"}]}
            ]
          },
          {"name": "merkleRoot", "type": "bytes32"},
          {"name": "nullifiers", "type": "bytes32[]"},
          {"name": "commitments", "type": "bytes32[]"},
          {
            "name": "boundParams",
            "type": "tuple",
            "components": [
              {"name": "treeNumber", "type": "uint16"},
              {"name": "minGasPrice", "type": "uint72"},
              {"name": "unshield", "type": "uint8"},
              {"name": "chainID", "type": "uint64"},
              {"name": "adaptContract", "type": "address"},
              {"name": "adaptParams", "type": "bytes32"},
              {
                "name": "commitmentCiphertext",
                "type": "tuple[]",
                "components": [
                  {"name": "ciphertext", "type": "bytes32[4]"},
                  {"name": "blindedSenderViewingKey", "type": "bytes32"},
                  {"name": "blindedReceiverViewingKey", "type": "bytes32"},
                  {"name": "annotationData", "type": "bytes"},
                  {"name": "memo", "type": "bytes"}
                ]
              }
            ]
          },
          {
            "name": "unshieldPreimage",
            "type": "tuple",
            "components": [
              {"name": "npk", "type": "bytes32"},
              {
                "name": "token",
                "type": "tuple",
                "components": [
                  {"name": "tokenType", "type": "uint8"},
                  {"name": "tokenAddress", "type": "address"},
                  {"name": "tokenSubID", "type": "uint256"}
                ]
              },
              {"name": "value", "type": "uint120"}
            ]
          }
        ]
      }
    ]
  }
]`

const railgunSmartWalletShieldABI = `[
  {
    "type": "function",
    "name": "shield",
    "stateMutability": "payable",
    "outputs": [],
    "inputs": [
      {
        "name": "_shieldRequests",
        "type": "tuple[]",
        "components": [
          {
            "name": "preimage",
            "type": "tuple",
            "components": [
              {"name": "npk", "type": "bytes32"},
              {
                "name": "token",
                "type": "tuple",
                "components": [
                  {"name": "tokenType", "type": "uint8"},
                  {"name": "tokenAddress", "type": "address"},
                  {"name": "tokenSubID", "type": "uint256"}
                ]
              },
              {"name": "value", "type": "uint120"}
            ]
          },
          {
            "name": "ciphertext",
            "type": "tuple",
            "components": [
              {"name": "encryptedBundle", "type": "bytes32[3]"},
              {"name": "shieldKey", "type": "bytes32"}
            ]
          }
        ]
      }
    ]
  }
]`

const relayAdaptABI = `[
  {
    "type": "function",
    "name": "multicall",
    "stateMutability": "payable",
    "outputs": [],
    "inputs": [
      {"name": "_requireSuccess", "type": "bool"},
      {
        "name": "_calls",
        "type": "tuple[]",
        "components": [
          {"name": "to", "type": "address"},
          {"name": "data", "type": "bytes"},
          {"name": "value", "type": "uint256"}
        ]
      }
    ]
  },
  {
    "type": "function",
    "name": "relay",
    "stateMutability": "payable",
    "outputs": [],
    "inputs": [
      {
        "name": "_transactions",
        "type": "tuple[]",
        "components": [
          {
            "name": "proof",
            "type": "tuple",
            "components": [
              {"name": "a", "type": "tuple", "components": [{"name": "x", "type": "uint256"}, {"name": "y", "type": "uint256"}]},
              {"name": "b", "type": "tuple", "components": [{"name": "x", "type": "uint256[2]"}, {"name": "y", "type": "uint256[2]"}]},
              {"name": "c", "type": "tuple", "components": [{"name": "x", "type": "uint256"}, {"name": "y", "type": "uint256"}]}
            ]
          },
          {"name": "merkleRoot", "type": "bytes32"},
          {"name": "nullifiers", "type": "bytes32[]"},
          {"name": "commitments", "type": "bytes32[]"},
          {
            "name": "boundParams",
            "type": "tuple",
            "components": [
              {"name": "treeNumber", "type": "uint16"},
              {"name": "minGasPrice", "type": "uint72"},
              {"name": "unshield", "type": "uint8"},
              {"name": "chainID", "type": "uint64"},
              {"name": "adaptContract", "type": "address"},
              {"name": "adaptParams", "type": "bytes32"},
              {
                "name": "commitmentCiphertext",
                "type": "tuple[]",
                "components": [
                  {"name": "ciphertext", "type": "bytes32[4]"},
                  {"name": "blindedSenderViewingKey", "type": "bytes32"},
                  {"name": "blindedReceiverViewingKey", "type": "bytes32"},
                  {"name": "annotationData", "type": "bytes"},
                  {"name": "memo", "type": "bytes"}
                ]
              }
            ]
          },
          {
            "name": "unshieldPreimage",
            "type": "tuple",
            "components": [
              {"name": "npk", "type": "bytes32"},
              {
                "name": "token",
                "type": "tuple",
                "components": [
                  {"name": "tokenType", "type": "uint8"},
                  {"name": "tokenAddress", "type": "address"},
                  {"name": "tokenSubID", "type": "uint256"}
                ]
              },
              {"name": "value", "type": "uint120"}
            ]
          }
        ]
      },
      {
        "name": "_actionData",
        "type": "tuple",
        "components": [
          {"name": "random", "type": "bytes31"},
          {"name": "requireSuccess", "type": "bool"},
          {"name": "minGasLimit", "type": "uint256"},
          {
            "name": "calls",
            "type": "tuple[]",
            "components": [
              {"name": "to", "type": "address"},
              {"name": "data", "type": "bytes"},
              {"name": "value", "type": "uint256"}
            ]
          }
        ]
      }
    ]
  },
  {
    "type": "function",
    "name": "shield",
    "stateMutability": "nonpayable",
    "outputs": [],
    "inputs": [
      {
        "name": "_shieldRequests",
        "type": "tuple[]",
        "components": [
          {
            "name": "preimage",
            "type": "tuple",
            "components": [
              {"name": "npk", "type": "bytes32"},
              {
                "name": "token",
                "type": "tuple",
                "components": [
                  {"name": "tokenType", "type": "uint8"},
                  {"name": "tokenAddress", "type": "address"},
                  {"name": "tokenSubID", "type": "uint256"}
                ]
              },
              {"name": "value", "type": "uint120"}
            ]
          },
          {
            "name": "ciphertext",
            "type": "tuple",
            "components": [
              {"name": "encryptedBundle", "type": "bytes32[3]"},
              {"name": "shieldKey", "type": "bytes32"}
            ]
          }
        ]
      }
    ]
  },
  {
    "type": "function",
    "name": "transfer",
    "stateMutability": "nonpayable",
    "outputs": [],
    "inputs": [
      {
        "name": "_transfers",
        "type": "tuple[]",
        "components": [
          {
            "name": "token",
            "type": "tuple",
            "components": [
              {"name": "tokenType", "type": "uint8"},
              {"name": "tokenAddress", "type": "address"},
              {"name": "tokenSubID", "type": "uint256"}
            ]
          },
          {"name": "to", "type": "address"},
          {"name": "value", "type": "uint256"}
        ]
      }
    ]
  },
  {
    "type": "function",
    "name": "unwrapBase",
    "stateMutability": "nonpayable",
    "outputs": [],
    "inputs": [{"name": "_amount", "type": "uint256"}]
  },
  {
    "type": "function",
    "name": "wrapBase",
    "stateMutability": "nonpayable",
    "outputs": [],
    "inputs": [{"name": "_amount", "type": "uint256"}]
  }
]`

const poseidonMerkleVerifierExecuteABI = `[
  {
    "type": "function",
    "name": "execute",
    "stateMutability": "nonpayable",
    "outputs": [],
    "inputs": [
      {
        "name": "_transactions",
        "type": "tuple[]",
        "components": [
          {
            "name": "proof",
            "type": "tuple",
            "components": [
              {"name": "a", "type": "tuple", "components": [{"name": "x", "type": "uint256"}, {"name": "y", "type": "uint256"}]},
              {"name": "b", "type": "tuple", "components": [{"name": "x", "type": "uint256[2]"}, {"name": "y", "type": "uint256[2]"}]},
              {"name": "c", "type": "tuple", "components": [{"name": "x", "type": "uint256"}, {"name": "y", "type": "uint256"}]}
            ]
          },
          {"name": "merkleRoot", "type": "bytes32"},
          {"name": "nullifiers", "type": "bytes32[]"},
          {"name": "commitments", "type": "bytes32[]"},
          {
            "name": "boundParams",
            "type": "tuple",
            "components": [
              {"name": "treeNumber", "type": "uint32"},
              {
                "name": "commitmentCiphertext",
                "type": "tuple[]",
                "components": [
                  {"name": "ciphertext", "type": "bytes"},
                  {"name": "blindedSenderViewingKey", "type": "bytes32"},
                  {"name": "blindedReceiverViewingKey", "type": "bytes32"}
                ]
              }
            ]
          },
          {
            "name": "unshieldPreimage",
            "type": "tuple",
            "components": [
              {"name": "npk", "type": "bytes32"},
              {
                "name": "token",
                "type": "tuple",
                "components": [
                  {"name": "tokenType", "type": "uint8"},
                  {"name": "tokenAddress", "type": "address"},
                  {"name": "tokenSubID", "type": "uint256"}
                ]
              },
              {"name": "value", "type": "uint120"}
            ]
          }
        ]
      },
      {
        "name": "_shieldRequests",
        "type": "tuple[]",
        "components": [
          {
            "name": "ciphertext",
            "type": "tuple",
            "components": [
              {"name": "encryptedBundle", "type": "bytes32[3]"},
              {"name": "shieldKey", "type": "bytes32"}
            ]
          },
          {
            "name": "preimage",
            "type": "tuple",
            "components": [
              {"name": "npk", "type": "bytes32"},
              {
                "name": "token",
                "type": "tuple",
                "components": [
                  {"name": "tokenType", "type": "uint8"},
                  {"name": "tokenAddress", "type": "address"},
                  {"name": "tokenSubID", "type": "uint256"}
                ]
              },
              {"name": "value", "type": "uint120"}
            ]
          }
        ]
      },
      {
        "name": "_globalBoundParams",
        "type": "tuple",
        "components": [
          {"name": "minGasPrice", "type": "uint128"},
          {"name": "chainID", "type": "uint128"},
          {"name": "senderCiphertext", "type": "bytes"},
          {"name": "to", "type": "address"},
          {"name": "data", "type": "bytes"}
        ]
      },
      {
        "name": "unshieldChangeCiphertext",
        "type": "tuple",
        "components": [
          {"name": "encryptedBundle", "type": "bytes32[3]"},
          {"name": "shieldKey", "type": "bytes32"}
        ]
      }
    ]
  }
]`

type abiG1Point struct {
	X *big.Int `abi:"x"`
	Y *big.Int `abi:"y"`
}

type abiG2Point struct {
	X [2]*big.Int `abi:"x"`
	Y [2]*big.Int `abi:"y"`
}

type abiSnarkProof struct {
	A abiG1Point `abi:"a"`
	B abiG2Point `abi:"b"`
	C abiG1Point `abi:"c"`
}

type abiTokenData struct {
	TokenType    uint8          `abi:"tokenType"`
	TokenAddress common.Address `abi:"tokenAddress"`
	TokenSubID   *big.Int       `abi:"tokenSubID"`
}

type abiCommitmentPreimage struct {
	NPK   [32]byte     `abi:"npk"`
	Token abiTokenData `abi:"token"`
	Value *big.Int     `abi:"value"`
}

type abiTransactionV2 struct {
	Proof            abiSnarkProof         `abi:"proof"`
	MerkleRoot       [32]byte              `abi:"merkleRoot"`
	Nullifiers       [][32]byte            `abi:"nullifiers"`
	Commitments      [][32]byte            `abi:"commitments"`
	BoundParams      BoundParamsV2         `abi:"boundParams"`
	UnshieldPreimage abiCommitmentPreimage `abi:"unshieldPreimage"`
}

type abiTransactionV3 struct {
	Proof            abiSnarkProof         `abi:"proof"`
	MerkleRoot       [32]byte              `abi:"merkleRoot"`
	Nullifiers       [][32]byte            `abi:"nullifiers"`
	Commitments      [][32]byte            `abi:"commitments"`
	BoundParams      LocalBoundParamsV3    `abi:"boundParams"`
	UnshieldPreimage abiCommitmentPreimage `abi:"unshieldPreimage"`
}

type abiShieldRequestV2 struct {
	Preimage   abiCommitmentPreimage `abi:"preimage"`
	Ciphertext abiShieldCiphertextV3 `abi:"ciphertext"`
}

type abiShieldCiphertextV3 struct {
	EncryptedBundle [3][32]byte `abi:"encryptedBundle"`
	ShieldKey       [32]byte    `abi:"shieldKey"`
}

type abiShieldRequestV3 struct {
	Ciphertext abiShieldCiphertextV3 `abi:"ciphertext"`
	Preimage   abiCommitmentPreimage `abi:"preimage"`
}

type RelayAdaptCall struct {
	To    common.Address `abi:"to"`
	Data  []byte         `abi:"data"`
	Value *big.Int       `abi:"value"`
}

type RelayAdaptTokenTransfer struct {
	Token railcrypto.TokenData
	To    common.Address
	Value *big.Int
}

type RelayAdaptActionData struct {
	Random         [31]byte         `abi:"random"`
	RequireSuccess bool             `abi:"requireSuccess"`
	MinGasLimit    *big.Int         `abi:"minGasLimit"`
	Calls          []RelayAdaptCall `abi:"calls"`
}

type abiRelayAdaptTokenTransfer struct {
	Token abiTokenData   `abi:"token"`
	To    common.Address `abi:"to"`
	Value *big.Int       `abi:"value"`
}

func EncodeShieldV2Calldata(shieldRequests []ShieldRequest) (string, error) {
	contractABI, err := abi.JSON(strings.NewReader(railgunSmartWalletShieldABI))
	if err != nil {
		return "", err
	}
	abiRequests := make([]abiShieldRequestV2, len(shieldRequests))
	for i, request := range shieldRequests {
		abiRequest, err := toABIShieldRequestV2(request)
		if err != nil {
			return "", fmt.Errorf("shieldRequest[%d]: %w", i, err)
		}
		abiRequests[i] = abiRequest
	}
	packed, err := contractABI.Pack("shield", abiRequests)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func EncodeTransactV2Calldata(transactions []TransactionStructV2) (string, error) {
	contractABI, err := abi.JSON(strings.NewReader(railgunSmartWalletTransactABI))
	if err != nil {
		return "", err
	}
	abiTransactions := make([]abiTransactionV2, len(transactions))
	for i, tx := range transactions {
		abiTx, err := toABITransactionV2(tx)
		if err != nil {
			return "", fmt.Errorf("transaction[%d]: %w", i, err)
		}
		abiTransactions[i] = abiTx
	}
	packed, err := contractABI.Pack("transact", abiTransactions)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func EncodeRelayAdaptV2Calldata(transactions []TransactionStructV2, actionData RelayAdaptActionData) (string, error) {
	contractABI, err := abi.JSON(strings.NewReader(relayAdaptABI))
	if err != nil {
		return "", err
	}
	abiTransactions := make([]abiTransactionV2, len(transactions))
	for i, tx := range transactions {
		abiTx, err := toABITransactionV2(tx)
		if err != nil {
			return "", fmt.Errorf("transaction[%d]: %w", i, err)
		}
		abiTransactions[i] = abiTx
	}
	packed, err := contractABI.Pack("relay", abiTransactions, normalizeRelayAdaptActionData(actionData))
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func EncodeRelayAdaptMulticallCalldata(requireSuccess bool, calls []RelayAdaptCall) (string, error) {
	contractABI, err := abi.JSON(strings.NewReader(relayAdaptABI))
	if err != nil {
		return "", err
	}
	packed, err := contractABI.Pack("multicall", requireSuccess, normalizeRelayAdaptCalls(calls))
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func EncodeRelayAdaptShieldCalldata(shieldRequests []ShieldRequest) (string, error) {
	contractABI, err := abi.JSON(strings.NewReader(relayAdaptABI))
	if err != nil {
		return "", err
	}
	abiRequests := make([]abiShieldRequestV2, len(shieldRequests))
	for i, request := range shieldRequests {
		abiRequest, err := toABIShieldRequestV2(request)
		if err != nil {
			return "", fmt.Errorf("shieldRequest[%d]: %w", i, err)
		}
		abiRequests[i] = abiRequest
	}
	packed, err := contractABI.Pack("shield", abiRequests)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func EncodeRelayAdaptTransferCalldata(transfers []RelayAdaptTokenTransfer) (string, error) {
	contractABI, err := abi.JSON(strings.NewReader(relayAdaptABI))
	if err != nil {
		return "", err
	}
	abiTransfers := make([]abiRelayAdaptTokenTransfer, len(transfers))
	for i, transfer := range transfers {
		abiTransfer, err := toABIRelayAdaptTokenTransfer(transfer)
		if err != nil {
			return "", fmt.Errorf("transfer[%d]: %w", i, err)
		}
		abiTransfers[i] = abiTransfer
	}
	packed, err := contractABI.Pack("transfer", abiTransfers)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func EncodeRelayAdaptWrapBaseCalldata(amount *big.Int) (string, error) {
	return encodeRelayAdaptAmountCalldata("wrapBase", amount)
}

func EncodeRelayAdaptUnwrapBaseCalldata(amount *big.Int) (string, error) {
	return encodeRelayAdaptAmountCalldata("unwrapBase", amount)
}

func DecodeTransactV2Calldata(calldata string) ([]TransactionStructV2, error) {
	contractABI, err := abi.JSON(strings.NewReader(railgunSmartWalletTransactABI))
	if err != nil {
		return nil, err
	}
	args, err := unpackMethodCalldata(contractABI, "transact", calldata)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Transactions []abiTransactionV2 `abi:"_transactions"`
	}
	if err := contractABI.Methods["transact"].Inputs.Copy(&decoded, args); err != nil {
		return nil, err
	}
	transactions := make([]TransactionStructV2, len(decoded.Transactions))
	for i, tx := range decoded.Transactions {
		transactions[i], err = fromABITransactionV2(tx)
		if err != nil {
			return nil, fmt.Errorf("transaction[%d]: %w", i, err)
		}
	}
	return transactions, nil
}

func DecodeRelayAdaptV2Calldata(calldata string) ([]TransactionStructV2, RelayAdaptActionData, error) {
	contractABI, err := abi.JSON(strings.NewReader(relayAdaptABI))
	if err != nil {
		return nil, RelayAdaptActionData{}, err
	}
	args, err := unpackMethodCalldata(contractABI, "relay", calldata)
	if err != nil {
		return nil, RelayAdaptActionData{}, err
	}
	var decoded struct {
		Transactions []abiTransactionV2   `abi:"_transactions"`
		ActionData   RelayAdaptActionData `abi:"_actionData"`
	}
	if err := contractABI.Methods["relay"].Inputs.Copy(&decoded, args); err != nil {
		return nil, RelayAdaptActionData{}, err
	}
	transactions := make([]TransactionStructV2, len(decoded.Transactions))
	for i, tx := range decoded.Transactions {
		transactions[i], err = fromABITransactionV2(tx)
		if err != nil {
			return nil, RelayAdaptActionData{}, fmt.Errorf("transaction[%d]: %w", i, err)
		}
	}
	return transactions, decoded.ActionData, nil
}

func EncodeExecuteV3ShieldCalldata(shieldRequests []ShieldRequest, chainID *big.Int) (string, error) {
	if chainID == nil {
		return "", fmt.Errorf("chainID is required")
	}
	contractABI, err := abi.JSON(strings.NewReader(poseidonMerkleVerifierExecuteABI))
	if err != nil {
		return "", err
	}
	abiRequests := make([]abiShieldRequestV3, len(shieldRequests))
	for i, request := range shieldRequests {
		abiRequest, err := toABIShieldRequestV3(request)
		if err != nil {
			return "", fmt.Errorf("shieldRequest[%d]: %w", i, err)
		}
		abiRequests[i] = abiRequest
	}
	emptyGlobalBoundParams := GlobalBoundParamsV3{
		MinGasPrice:      big.NewInt(0),
		ChainID:          cloneBigInt(chainID),
		SenderCiphertext: nil,
		To:               common.Address{},
		Data:             nil,
	}
	packed, err := contractABI.Pack(
		"execute",
		[]abiTransactionV3{},
		abiRequests,
		emptyGlobalBoundParams,
		abiShieldCiphertextV3{},
	)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func DecodeExecuteV3TransactCalldata(calldata string) ([]TransactionStructV3, GlobalBoundParamsV3, error) {
	contractABI, err := abi.JSON(strings.NewReader(poseidonMerkleVerifierExecuteABI))
	if err != nil {
		return nil, GlobalBoundParamsV3{}, err
	}
	args, err := unpackMethodCalldata(contractABI, "execute", calldata)
	if err != nil {
		return nil, GlobalBoundParamsV3{}, err
	}
	var decoded struct {
		Transactions      []abiTransactionV3    `abi:"_transactions"`
		ShieldRequests    []abiShieldRequestV3  `abi:"_shieldRequests"`
		GlobalBoundParams GlobalBoundParamsV3   `abi:"_globalBoundParams"`
		UnshieldChange    abiShieldCiphertextV3 `abi:"unshieldChangeCiphertext"`
	}
	if err := contractABI.Methods["execute"].Inputs.Copy(&decoded, args); err != nil {
		return nil, GlobalBoundParamsV3{}, err
	}
	transactions := make([]TransactionStructV3, len(decoded.Transactions))
	for i, tx := range decoded.Transactions {
		transactions[i], err = fromABITransactionV3(tx, decoded.GlobalBoundParams)
		if err != nil {
			return nil, GlobalBoundParamsV3{}, fmt.Errorf("transaction[%d]: %w", i, err)
		}
	}
	return transactions, decoded.GlobalBoundParams, nil
}

func EncodeExecuteV3TransactCalldata(transactions []TransactionStructV3) (string, error) {
	if len(transactions) == 0 {
		return "", fmt.Errorf("no transactions to transact")
	}
	contractABI, err := abi.JSON(strings.NewReader(poseidonMerkleVerifierExecuteABI))
	if err != nil {
		return "", err
	}
	abiTransactions := make([]abiTransactionV3, len(transactions))
	for i, tx := range transactions {
		abiTx, err := toABITransactionV3(tx)
		if err != nil {
			return "", fmt.Errorf("transaction[%d]: %w", i, err)
		}
		abiTransactions[i] = abiTx
	}
	packed, err := contractABI.Pack(
		"execute",
		abiTransactions,
		[]abiShieldRequestV3{},
		transactions[0].BoundParams.Global,
		abiShieldCiphertextV3{},
	)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func unpackMethodCalldata(contractABI abi.ABI, methodName string, calldata string) ([]any, error) {
	data, err := railcrypto.HexToBytes(calldata)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("calldata too short")
	}
	method, err := contractABI.MethodById(data[:4])
	if err != nil {
		return nil, err
	}
	if method.Name != methodName {
		return nil, fmt.Errorf("method %s invalid: expected %s", method.Name, methodName)
	}
	return method.Inputs.Unpack(data[4:])
}

func toABITransactionV2(tx TransactionStructV2) (abiTransactionV2, error) {
	merkleRoot, err := Bytes32FromHex(tx.MerkleRoot)
	if err != nil {
		return abiTransactionV2{}, fmt.Errorf("merkleRoot: %w", err)
	}
	nullifiers, err := bytes32SliceFromHex(tx.Nullifiers)
	if err != nil {
		return abiTransactionV2{}, fmt.Errorf("nullifiers: %w", err)
	}
	commitments, err := bytes32SliceFromHex(tx.Commitments)
	if err != nil {
		return abiTransactionV2{}, fmt.Errorf("commitments: %w", err)
	}
	preimage, err := toABICommitmentPreimage(tx.UnshieldPreimage)
	if err != nil {
		return abiTransactionV2{}, fmt.Errorf("unshieldPreimage: %w", err)
	}
	return abiTransactionV2{
		Proof:            toABISnarkProof(tx.Proof),
		MerkleRoot:       merkleRoot,
		Nullifiers:       nullifiers,
		Commitments:      commitments,
		BoundParams:      tx.BoundParams,
		UnshieldPreimage: preimage,
	}, nil
}

func fromABITransactionV2(tx abiTransactionV2) (TransactionStructV2, error) {
	preimage, err := fromABICommitmentPreimage(tx.UnshieldPreimage)
	if err != nil {
		return TransactionStructV2{}, fmt.Errorf("unshieldPreimage: %w", err)
	}
	return TransactionStructV2{
		TXIDVersion:      TXIDVersionV2PoseidonMerkle,
		Proof:            fromABISnarkProof(tx.Proof),
		MerkleRoot:       bytes32Hex(tx.MerkleRoot),
		Nullifiers:       bytes32SliceHex(tx.Nullifiers),
		Commitments:      bytes32SliceHex(tx.Commitments),
		BoundParams:      tx.BoundParams,
		UnshieldPreimage: preimage,
	}, nil
}

func toABITransactionV3(tx TransactionStructV3) (abiTransactionV3, error) {
	merkleRoot, err := Bytes32FromHex(tx.MerkleRoot)
	if err != nil {
		return abiTransactionV3{}, fmt.Errorf("merkleRoot: %w", err)
	}
	nullifiers, err := bytes32SliceFromHex(tx.Nullifiers)
	if err != nil {
		return abiTransactionV3{}, fmt.Errorf("nullifiers: %w", err)
	}
	commitments, err := bytes32SliceFromHex(tx.Commitments)
	if err != nil {
		return abiTransactionV3{}, fmt.Errorf("commitments: %w", err)
	}
	preimage, err := toABICommitmentPreimage(tx.UnshieldPreimage)
	if err != nil {
		return abiTransactionV3{}, fmt.Errorf("unshieldPreimage: %w", err)
	}
	return abiTransactionV3{
		Proof:            toABISnarkProof(tx.Proof),
		MerkleRoot:       merkleRoot,
		Nullifiers:       nullifiers,
		Commitments:      commitments,
		BoundParams:      tx.BoundParams.Local,
		UnshieldPreimage: preimage,
	}, nil
}

func fromABITransactionV3(tx abiTransactionV3, globalBoundParams GlobalBoundParamsV3) (TransactionStructV3, error) {
	preimage, err := fromABICommitmentPreimage(tx.UnshieldPreimage)
	if err != nil {
		return TransactionStructV3{}, fmt.Errorf("unshieldPreimage: %w", err)
	}
	return TransactionStructV3{
		TXIDVersion: TXIDVersionV3PoseidonMerkle,
		Proof:       fromABISnarkProof(tx.Proof),
		MerkleRoot:  bytes32Hex(tx.MerkleRoot),
		Nullifiers:  bytes32SliceHex(tx.Nullifiers),
		Commitments: bytes32SliceHex(tx.Commitments),
		BoundParams: BoundParamsV3{
			Local:  tx.BoundParams,
			Global: globalBoundParams,
		},
		UnshieldPreimage: preimage,
	}, nil
}

func toABIShieldRequestV2(request ShieldRequest) (abiShieldRequestV2, error) {
	preimage, err := toABICommitmentPreimage(request.Preimage)
	if err != nil {
		return abiShieldRequestV2{}, fmt.Errorf("preimage: %w", err)
	}
	ciphertext, err := toABIShieldCiphertext(request.Ciphertext)
	if err != nil {
		return abiShieldRequestV2{}, fmt.Errorf("ciphertext: %w", err)
	}
	return abiShieldRequestV2{Preimage: preimage, Ciphertext: ciphertext}, nil
}

func toABIShieldRequestV3(request ShieldRequest) (abiShieldRequestV3, error) {
	preimage, err := toABICommitmentPreimage(request.Preimage)
	if err != nil {
		return abiShieldRequestV3{}, fmt.Errorf("preimage: %w", err)
	}
	ciphertext, err := toABIShieldCiphertext(request.Ciphertext)
	if err != nil {
		return abiShieldRequestV3{}, fmt.Errorf("ciphertext: %w", err)
	}
	return abiShieldRequestV3{Ciphertext: ciphertext, Preimage: preimage}, nil
}

func toABIShieldCiphertext(ciphertext ShieldCiphertext) (abiShieldCiphertextV3, error) {
	var encryptedBundle [3][32]byte
	for i, chunk := range ciphertext.EncryptedBundle {
		decoded, err := Bytes32FromHex(chunk)
		if err != nil {
			return abiShieldCiphertextV3{}, fmt.Errorf("encryptedBundle[%d]: %w", i, err)
		}
		encryptedBundle[i] = decoded
	}
	shieldKey, err := Bytes32FromHex(ciphertext.ShieldKey)
	if err != nil {
		return abiShieldCiphertextV3{}, fmt.Errorf("shieldKey: %w", err)
	}
	return abiShieldCiphertextV3{
		EncryptedBundle: encryptedBundle,
		ShieldKey:       shieldKey,
	}, nil
}

func toABISnarkProof(snarkProof ContractSnarkProof) abiSnarkProof {
	return abiSnarkProof{
		A: abiG1Point{X: cloneBigInt(snarkProof.A.X), Y: cloneBigInt(snarkProof.A.Y)},
		B: abiG2Point{
			X: [2]*big.Int{cloneBigInt(snarkProof.B.X[0]), cloneBigInt(snarkProof.B.X[1])},
			Y: [2]*big.Int{cloneBigInt(snarkProof.B.Y[0]), cloneBigInt(snarkProof.B.Y[1])},
		},
		C: abiG1Point{X: cloneBigInt(snarkProof.C.X), Y: cloneBigInt(snarkProof.C.Y)},
	}
}

func fromABISnarkProof(snarkProof abiSnarkProof) ContractSnarkProof {
	return ContractSnarkProof{
		A: ContractG1Point{X: cloneBigInt(snarkProof.A.X), Y: cloneBigInt(snarkProof.A.Y)},
		B: ContractG2Point{
			X: [2]*big.Int{cloneBigInt(snarkProof.B.X[0]), cloneBigInt(snarkProof.B.X[1])},
			Y: [2]*big.Int{cloneBigInt(snarkProof.B.Y[0]), cloneBigInt(snarkProof.B.Y[1])},
		},
		C: ContractG1Point{X: cloneBigInt(snarkProof.C.X), Y: cloneBigInt(snarkProof.C.Y)},
	}
}

func toABICommitmentPreimage(preimage CommitmentPreimage) (abiCommitmentPreimage, error) {
	npk, err := Bytes32FromHex(preimage.NPK)
	if err != nil {
		return abiCommitmentPreimage{}, fmt.Errorf("npk: %w", err)
	}
	token, err := toABITokenData(preimage.Token)
	if err != nil {
		return abiCommitmentPreimage{}, err
	}
	if preimage.Value == nil {
		return abiCommitmentPreimage{}, fmt.Errorf("value is required")
	}
	return abiCommitmentPreimage{
		NPK:   npk,
		Token: token,
		Value: cloneBigInt(preimage.Value),
	}, nil
}

func fromABICommitmentPreimage(preimage abiCommitmentPreimage) (CommitmentPreimage, error) {
	token, err := fromABITokenData(preimage.Token)
	if err != nil {
		return CommitmentPreimage{}, err
	}
	return CommitmentPreimage{
		NPK:   bytes32Hex(preimage.NPK),
		Token: token,
		Value: cloneBigInt(preimage.Value),
	}, nil
}

func toABITokenData(token railcrypto.TokenData) (abiTokenData, error) {
	if token.TokenType < 0 || token.TokenType > 255 {
		return abiTokenData{}, fmt.Errorf("invalid token type %d", token.TokenType)
	}
	tokenAddress, err := AddressFromHex(token.TokenAddress)
	if err != nil {
		return abiTokenData{}, fmt.Errorf("token address: %w", err)
	}
	tokenSubID, err := railcrypto.NumberishToBigInt(token.TokenSubID)
	if err != nil {
		return abiTokenData{}, fmt.Errorf("token sub id: %w", err)
	}
	return abiTokenData{
		TokenType:    uint8(token.TokenType),
		TokenAddress: tokenAddress,
		TokenSubID:   tokenSubID,
	}, nil
}

func fromABITokenData(token abiTokenData) (railcrypto.TokenData, error) {
	return railcrypto.SerializeTokenData(
		strings.ToLower(token.TokenAddress.Hex()),
		int(token.TokenType),
		token.TokenSubID.String(),
	)
}

func toABIRelayAdaptTokenTransfer(transfer RelayAdaptTokenTransfer) (abiRelayAdaptTokenTransfer, error) {
	token, err := toABITokenData(transfer.Token)
	if err != nil {
		return abiRelayAdaptTokenTransfer{}, err
	}
	return abiRelayAdaptTokenTransfer{
		Token: token,
		To:    transfer.To,
		Value: bigIntOrZero(transfer.Value),
	}, nil
}

func normalizeRelayAdaptActionData(actionData RelayAdaptActionData) RelayAdaptActionData {
	return RelayAdaptActionData{
		Random:         actionData.Random,
		RequireSuccess: actionData.RequireSuccess,
		MinGasLimit:    bigIntOrZero(actionData.MinGasLimit),
		Calls:          normalizeRelayAdaptCalls(actionData.Calls),
	}
}

func normalizeRelayAdaptCalls(calls []RelayAdaptCall) []RelayAdaptCall {
	out := make([]RelayAdaptCall, len(calls))
	for i, call := range calls {
		out[i] = RelayAdaptCall{
			To:    call.To,
			Data:  append([]byte(nil), call.Data...),
			Value: bigIntOrZero(call.Value),
		}
	}
	return out
}

func encodeRelayAdaptAmountCalldata(method string, amount *big.Int) (string, error) {
	contractABI, err := abi.JSON(strings.NewReader(relayAdaptABI))
	if err != nil {
		return "", err
	}
	packed, err := contractABI.Pack(method, bigIntOrZero(amount))
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func bigIntOrZero(value *big.Int) *big.Int {
	if value == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(value)
}

func bytes32SliceFromHex(values []string) ([][32]byte, error) {
	out := make([][32]byte, len(values))
	for i, value := range values {
		decoded, err := Bytes32FromHex(value)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out[i] = decoded
	}
	return out, nil
}

func bytes32SliceHex(values [][32]byte) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = bytes32Hex(value)
	}
	return out
}
