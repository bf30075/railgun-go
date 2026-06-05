package proof

import (
	"encoding/json"
	"os"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func TestSignPublicInputsRailgunMatchesTypeScript(t *testing.T) {
	fixture := loadTransactionRequestSignatureFixtures(t)
	privateKey, err := railcrypto.HexToBytes(fixture.Inputs.SpendingPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		inputs    publicInputsRailgunFixture
		signature railgunSignatureFixture
	}{
		{name: "v2", inputs: fixture.V2.PublicInputs, signature: fixture.Signatures.V2},
		{name: "v3", inputs: fixture.V3.PublicInputs, signature: fixture.Signatures.V3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publicInputs := PublicInputsRailgun{
				MerkleRoot:      mustNumberish(t, test.inputs.MerkleRoot),
				BoundParamsHash: mustNumberish(t, test.inputs.BoundParamsHash),
				Nullifiers:      mustNumberishSlice(t, test.inputs.Nullifiers),
				CommitmentsOut:  mustNumberishSlice(t, test.inputs.CommitmentsOut),
			}
			message, err := HashPublicInputsRailgun(publicInputs)
			if err != nil {
				t.Fatal(err)
			}
			if message.String() != test.signature.Message {
				t.Fatalf("expected message %s, got %s", test.signature.Message, message)
			}
			signature, err := SignPublicInputsRailgun(privateKey, publicInputs)
			if err != nil {
				t.Fatal(err)
			}
			if signature.R8[0].String() != test.signature.Signature.R8[0] {
				t.Fatalf("expected R8[0] %s, got %s", test.signature.Signature.R8[0], signature.R8[0])
			}
			if signature.R8[1].String() != test.signature.Signature.R8[1] {
				t.Fatalf("expected R8[1] %s, got %s", test.signature.Signature.R8[1], signature.R8[1])
			}
			if signature.S.String() != test.signature.Signature.S {
				t.Fatalf("expected S %s, got %s", test.signature.Signature.S, signature.S)
			}
		})
	}
}

type transactionRequestSignatureFixtureFile struct {
	TransactionRequestFixtures transactionRequestSignatureFixtureSet `json:"transactionRequestFixtures"`
}

type transactionRequestSignatureFixtureSet struct {
	Inputs     transactionRequestSignatureInputs `json:"inputs"`
	V2         transactionRequestPublicFixture   `json:"v2"`
	V3         transactionRequestPublicFixture   `json:"v3"`
	Signatures transactionRequestSignatures      `json:"signatures"`
}

type transactionRequestSignatureInputs struct {
	SpendingPrivateKey string `json:"spendingPrivateKey"`
}

type transactionRequestPublicFixture struct {
	PublicInputs publicInputsRailgunFixture `json:"publicInputs"`
}

type publicInputsRailgunFixture struct {
	MerkleRoot      string   `json:"merkleRoot"`
	BoundParamsHash string   `json:"boundParamsHash"`
	Nullifiers      []string `json:"nullifiers"`
	CommitmentsOut  []string `json:"commitmentsOut"`
}

type transactionRequestSignatures struct {
	V2 railgunSignatureFixture `json:"v2"`
	V3 railgunSignatureFixture `json:"v3"`
}

type railgunSignatureFixture struct {
	Message   string                   `json:"message"`
	Signature railgunPoseidonSignature `json:"signature"`
}

type railgunPoseidonSignature struct {
	R8 [2]string `json:"R8"`
	S  string    `json:"S"`
}

func loadTransactionRequestSignatureFixtures(t *testing.T) transactionRequestSignatureFixtureSet {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures transactionRequestSignatureFixtureFile
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.TransactionRequestFixtures
}
