package railcrypto

import (
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

func TestPoseidonVectorsMatchTypeScript(t *testing.T) {
	tests := []struct {
		name     string
		inputs   []*big.Int
		expected string
	}{
		{
			name:     "zero one",
			inputs:   []*big.Int{big.NewInt(0), big.NewInt(1)},
			expected: "12583541437132735734108669866114103169564651237895298778035846191048104863326",
		},
		{
			name:     "one two",
			inputs:   []*big.Int{big.NewInt(1), big.NewInt(2)},
			expected: "7853200120776062878684798364095072458815029376092732009249414926327459813530",
		},
		{
			name:     "one two three four",
			inputs:   []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)},
			expected: "18821383157269793795438455681495246036402687001665670618754263018637548127333",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Poseidon(test.inputs...)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != test.expected {
				t.Fatalf("expected %s, got %s", test.expected, got)
			}
		})
	}
}

func TestRailgunCryptoVectorsFromPOIReference(t *testing.T) {
	spendingPublicKey := [2]*big.Int{
		mustDec(t, "15684838006997671713939066069845237677934334329285343229142447933587909549584"),
		mustDec(t, "11878614856120328179849762231924033298788609151532558727282528569229552954628"),
	}
	nullifyingKey := mustDec(t, "8368299126798249740586535953124199418524409103803955764525436743456763691384")

	masterPublicKey, err := MasterPublicKey(spendingPublicKey, nullifyingKey)
	if err != nil {
		t.Fatal(err)
	}
	if masterPublicKey.String() != "20060431504059690749153982049210720252589378133547582826474262520121417617087" {
		t.Fatalf("unexpected master public key: %s", masterPublicKey)
	}

	notePublicKey, err := NotePublicKey(masterPublicKey, "67c600e777b86d3a1e72a53092e9fe85")
	if err != nil {
		t.Fatal(err)
	}
	if notePublicKey.String() != "6401386539363233023821237080626891507664131047949709897410333742190241828916" {
		t.Fatalf("unexpected note public key: %s", notePublicKey)
	}

	shieldCommitment, err := NoteHash(notePublicKey, "0000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e0", mustDec(t, "109725000000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	if shieldCommitment.String() != "6442080113031815261226726790601252395803415545769290265212232865825296902085" {
		t.Fatalf("unexpected shield commitment: %s", shieldCommitment)
	}

	commitmentHex, err := BigIntToHex(shieldCommitment, 32, false)
	if err != nil {
		t.Fatal(err)
	}
	blinded, err := BlindedCommitment(commitmentHex, notePublicKey, big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
	if blinded != "0x1add5dfd0299e9dc5af6fdfc0d86c0aaad29f9f9ca61674f67d3d185e28802e2" {
		t.Fatalf("unexpected blinded commitment: %s", blinded)
	}

	nullifier, err := Nullifier(nullifyingKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	if nullifier.String() != "2488005839880174281371566850742862351218389849446606448043615745372921337838" {
		t.Fatalf("unexpected nullifier: %s", nullifier)
	}
}

func TestNullifierVectorsMatchTypeScript(t *testing.T) {
	tests := []struct {
		privateKey string
		position   uint64
		expected   string
	}{
		{
			privateKey: "08ad9143ae793cdfe94b77e4e52bc4e9f13666966cffa395e3d412ea4e20480f",
			position:   0,
			expected:   "03f68801f3ee2ed10178c162b4f7f1bd466bc9718f4f98175fc04934c5caba6e",
		},
		{
			privateKey: "11299eb10424d82de500a440a2874d12f7c477afb5a3eb31dbb96295cdbcf165",
			position:   12,
			expected:   "1aeadb64bf8faff93dfe26bcf0b2e2d0e9724293cc7a455f028b6accabee13b8",
		},
		{
			privateKey: "09b57736523cda7412ddfed0d2f1f4a86d8a7e26de6b0638cd092c2a2b524705",
			position:   6500,
			expected:   "091961ce11c244db49a25668e57dfa2b5ffb1fe63055dd64a14af6f2be58b0e7",
		},
	}

	for _, test := range tests {
		privateKey, err := HexToBigInt(test.privateKey)
		if err != nil {
			t.Fatal(err)
		}
		nullifier, err := Nullifier(privateKey, test.position)
		if err != nil {
			t.Fatal(err)
		}
		hexNullifier, err := BigIntToHex(nullifier, 32, false)
		if err != nil {
			t.Fatal(err)
		}
		if hexNullifier != test.expected {
			t.Fatalf("expected %s, got %s", test.expected, hexNullifier)
		}
	}
}

func TestEDDSAAndED25519Helpers(t *testing.T) {
	privateKey, err := HexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := Poseidon(big.NewInt(1), big.NewInt(2))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicSpendingKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignPoseidon(privateKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPoseidon(msg, sig, pub) {
		t.Fatalf("expected poseidon signature to verify")
	}

	viewPub, err := PublicViewingKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	edSig, err := SignED25519([]byte("railgun"), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyED25519([]byte("railgun"), edSig, viewPub) {
		t.Fatalf("expected ed25519 signature to verify")
	}
}

func TestExportedCryptoFixturesMatchTypeScript(t *testing.T) {
	fixtures := loadCryptoFixtures(t)

	for _, vector := range fixtures.PoseidonVectors {
		t.Run("poseidon "+vector.Name, func(t *testing.T) {
			inputs := make([]*big.Int, len(vector.Inputs))
			for i, input := range vector.Inputs {
				inputs[i] = mustDec(t, input)
			}
			got, err := Poseidon(inputs...)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != vector.Output {
				t.Fatalf("expected %s, got %s", vector.Output, got)
			}
		})
	}

	privateKey, err := HexToBytes(fixtures.KeyVector.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	spendingPublicKey, err := PublicSpendingKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	assertBigIntString(t, spendingPublicKey[0], fixtures.KeyVector.SpendingPublicKey[0], "spendingPublicKey[0]")
	assertBigIntString(t, spendingPublicKey[1], fixtures.KeyVector.SpendingPublicKey[1], "spendingPublicKey[1]")

	message := mustDec(t, fixtures.KeyVector.PoseidonMessage)
	signature, err := SignPoseidon(privateKey, message)
	if err != nil {
		t.Fatal(err)
	}
	assertBigIntString(t, signature.R8[0], fixtures.KeyVector.PoseidonSignature.R8[0], "poseidonSignature.R8[0]")
	assertBigIntString(t, signature.R8[1], fixtures.KeyVector.PoseidonSignature.R8[1], "poseidonSignature.R8[1]")
	assertBigIntString(t, signature.S, fixtures.KeyVector.PoseidonSignature.S, "poseidonSignature.S")
	if !fixtures.KeyVector.PoseidonSignatureVerified {
		t.Fatal("fixture expected TypeScript Poseidon signature verification to pass")
	}
	if !VerifyPoseidon(message, signature, spendingPublicKey) {
		t.Fatal("expected Go Poseidon signature verification to pass")
	}

	viewingPublicKey, err := PublicViewingKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := BytesToHex(viewingPublicKey, false); got != fixtures.KeyVector.PublicViewingKey {
		t.Fatalf("expected public viewing key %s, got %s", fixtures.KeyVector.PublicViewingKey, got)
	}
	privateScalar, err := PrivateScalarFromPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	assertBigIntString(t, privateScalar, fixtures.KeyVector.PrivateScalar, "privateScalar")
	sharedSymmetricKey, err := SharedSymmetricKey(privateKey, viewingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := BytesToHex(sharedSymmetricKey, false); got != fixtures.KeyVector.SharedSymmetricKey {
		t.Fatalf("expected shared symmetric key %s, got %s", fixtures.KeyVector.SharedSymmetricKey, got)
	}
	receiverViewingPublicKey, err := HexToBytes(fixtures.KeyVector.NoteBlinding.ReceiverViewingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	blindedSenderViewingKey, blindedReceiverViewingKey, err := NoteBlindingKeys(
		viewingPublicKey,
		receiverViewingPublicKey,
		fixtures.KeyVector.NoteBlinding.SharedRandom,
		fixtures.KeyVector.NoteBlinding.SenderRandom,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := BytesToHex(blindedSenderViewingKey, false); got != fixtures.KeyVector.NoteBlinding.BlindedSenderViewingKey {
		t.Fatalf("expected blinded sender viewing key %s, got %s", fixtures.KeyVector.NoteBlinding.BlindedSenderViewingKey, got)
	}
	if got := BytesToHex(blindedReceiverViewingKey, false); got != fixtures.KeyVector.NoteBlinding.BlindedReceiverViewingKey {
		t.Fatalf("expected blinded receiver viewing key %s, got %s", fixtures.KeyVector.NoteBlinding.BlindedReceiverViewingKey, got)
	}
	unblindedSenderViewingKey, err := UnblindNoteKey(
		blindedSenderViewingKey,
		fixtures.KeyVector.NoteBlinding.SharedRandom,
		fixtures.KeyVector.NoteBlinding.SenderRandom,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := BytesToHex(unblindedSenderViewingKey, false); got != fixtures.KeyVector.NoteBlinding.UnblindedSenderViewingKey {
		t.Fatalf("expected unblinded sender viewing key %s, got %s", fixtures.KeyVector.NoteBlinding.UnblindedSenderViewingKey, got)
	}
	legacySharedSymmetricKey, err := SharedSymmetricKeyLegacy(privateKey, viewingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := BytesToHex(legacySharedSymmetricKey, false); got != fixtures.KeyVector.LegacyNoteBlinding.SharedSymmetricKey {
		t.Fatalf("expected legacy shared symmetric key %s, got %s", fixtures.KeyVector.LegacyNoteBlinding.SharedSymmetricKey, got)
	}
	legacyBlindedSenderViewingKey, legacyBlindedReceiverViewingKey, err := NoteBlindingKeysLegacy(
		viewingPublicKey,
		receiverViewingPublicKey,
		fixtures.KeyVector.LegacyNoteBlinding.SharedRandom,
		fixtures.KeyVector.LegacyNoteBlinding.SenderRandom,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := BytesToHex(legacyBlindedSenderViewingKey, false); got != fixtures.KeyVector.LegacyNoteBlinding.BlindedSenderViewingKey {
		t.Fatalf("expected legacy blinded sender viewing key %s, got %s", fixtures.KeyVector.LegacyNoteBlinding.BlindedSenderViewingKey, got)
	}
	if got := BytesToHex(legacyBlindedReceiverViewingKey, false); got != fixtures.KeyVector.LegacyNoteBlinding.BlindedReceiverViewingKey {
		t.Fatalf("expected legacy blinded receiver viewing key %s, got %s", fixtures.KeyVector.LegacyNoteBlinding.BlindedReceiverViewingKey, got)
	}
	legacyUnblindedSenderViewingKey, err := UnblindNoteKeyLegacy(
		legacyBlindedSenderViewingKey,
		fixtures.KeyVector.LegacyNoteBlinding.SharedRandom,
		fixtures.KeyVector.LegacyNoteBlinding.SenderRandom,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := BytesToHex(legacyUnblindedSenderViewingKey, false); got != fixtures.KeyVector.LegacyNoteBlinding.UnblindedSenderViewingKey {
		t.Fatalf("expected legacy unblinded sender viewing key %s, got %s", fixtures.KeyVector.LegacyNoteBlinding.UnblindedSenderViewingKey, got)
	}
	legacyUnblindedReceiverViewingKey, err := UnblindNoteKeyLegacy(
		legacyBlindedReceiverViewingKey,
		fixtures.KeyVector.LegacyNoteBlinding.SharedRandom,
		fixtures.KeyVector.LegacyNoteBlinding.SenderRandom,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := BytesToHex(legacyUnblindedReceiverViewingKey, false); got != fixtures.KeyVector.LegacyNoteBlinding.UnblindedReceiverViewingKey {
		t.Fatalf("expected legacy unblinded receiver viewing key %s, got %s", fixtures.KeyVector.LegacyNoteBlinding.UnblindedReceiverViewingKey, got)
	}
	ed25519Message, err := HexToBytes(fixtures.KeyVector.ED25519Message)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Signature, err := SignED25519(ed25519Message, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := BytesToHex(ed25519Signature, false); got != fixtures.KeyVector.ED25519Signature {
		t.Fatalf("expected ed25519 signature %s, got %s", fixtures.KeyVector.ED25519Signature, got)
	}
	if !fixtures.KeyVector.ED25519SignatureVerified {
		t.Fatal("fixture expected TypeScript Ed25519 signature verification to pass")
	}
	if !VerifyED25519(ed25519Message, ed25519Signature, viewingPublicKey) {
		t.Fatal("expected Go Ed25519 signature verification to pass")
	}

	for _, vector := range fixtures.TokenVectors {
		t.Run("token "+vector.Name, func(t *testing.T) {
			tokenHash, err := TokenDataHash(vector.TokenData)
			if err != nil {
				t.Fatal(err)
			}
			if tokenHash != vector.TokenHash {
				t.Fatalf("expected token hash %s, got %s", vector.TokenHash, tokenHash)
			}
			noteHash, err := UnshieldNoteHash(vector.NotePublicKey, vector.TokenData, mustDec(t, vector.Value))
			if err != nil {
				t.Fatal(err)
			}
			assertBigIntString(t, noteHash, vector.NoteHash, "noteHash")
		})
	}

	poi := fixtures.POIReference
	poiSpendingPublicKey := [2]*big.Int{
		mustDec(t, poi.SpendingPublicKey[0]),
		mustDec(t, poi.SpendingPublicKey[1]),
	}
	poiNullifyingKey := mustDec(t, poi.NullifyingKey)
	masterPublicKey, err := MasterPublicKey(poiSpendingPublicKey, poiNullifyingKey)
	if err != nil {
		t.Fatal(err)
	}
	assertBigIntString(t, masterPublicKey, poi.MasterPublicKey, "masterPublicKey")
	notePublicKey, err := NotePublicKey(masterPublicKey, poi.Random)
	if err != nil {
		t.Fatal(err)
	}
	assertBigIntString(t, notePublicKey, poi.NotePublicKey, "notePublicKey")
	shieldCommitment, err := NoteHash(notePublicKey, poi.Token, mustDec(t, poi.Value))
	if err != nil {
		t.Fatal(err)
	}
	assertBigIntString(t, shieldCommitment, poi.ShieldCommitment, "shieldCommitment")
	shieldCommitmentHex, err := BigIntToHex(shieldCommitment, 32, false)
	if err != nil {
		t.Fatal(err)
	}
	if shieldCommitmentHex != poi.ShieldCommitmentHex {
		t.Fatalf("expected shield commitment hex %s, got %s", poi.ShieldCommitmentHex, shieldCommitmentHex)
	}
	blindedCommitment, err := BlindedCommitment(shieldCommitmentHex, notePublicKey, mustDec(t, poi.GlobalTreePosition))
	if err != nil {
		t.Fatal(err)
	}
	if blindedCommitment != poi.BlindedCommitment {
		t.Fatalf("expected blinded commitment %s, got %s", poi.BlindedCommitment, blindedCommitment)
	}
	nullifier, err := Nullifier(poiNullifyingKey, poi.NotePosition)
	if err != nil {
		t.Fatal(err)
	}
	assertBigIntString(t, nullifier, poi.Nullifier, "nullifier")
	nullifierHex, err := BigIntToHex(nullifier, 32, false)
	if err != nil {
		t.Fatal(err)
	}
	if nullifierHex != poi.NullifierHex {
		t.Fatalf("expected nullifier hex %s, got %s", poi.NullifierHex, nullifierHex)
	}
	tokenDataHash, err := TokenDataHashERC20(poi.Token)
	if err != nil {
		t.Fatal(err)
	}
	if tokenDataHash != poi.TokenDataHashERC20 {
		t.Fatalf("expected token data hash %s, got %s", poi.TokenDataHashERC20, tokenDataHash)
	}
}

func TestAESEncryptionFixturesMatchTypeScript(t *testing.T) {
	fixtures := loadEncryptionFixtures(t)

	gcmCiphertext, err := AESGCMEncryptHex(fixtures.AESGCM.Plaintext, fixtures.AESGCM.Key, fixtures.AESGCM.IV)
	if err != nil {
		t.Fatal(err)
	}
	if gotJSON, expectedJSON := mustJSON(t, gcmCiphertext), mustJSON(t, fixtures.AESGCM.Ciphertext); gotJSON != expectedJSON {
		t.Fatalf("expected AES-GCM ciphertext %s, got %s", expectedJSON, gotJSON)
	}
	gcmDecrypted, err := AESGCMDecryptHex(fixtures.AESGCM.Ciphertext, fixtures.AESGCM.Key)
	if err != nil {
		t.Fatal(err)
	}
	if gotJSON, expectedJSON := mustJSON(t, gcmDecrypted), mustJSON(t, fixtures.AESGCM.Decrypted); gotJSON != expectedJSON {
		t.Fatalf("expected AES-GCM plaintext %s, got %s", expectedJSON, gotJSON)
	}

	ctrCiphertext, err := AESCTREncryptHex(fixtures.AESCTR.Plaintext, fixtures.AESCTR.Key, fixtures.AESCTR.IV)
	if err != nil {
		t.Fatal(err)
	}
	if gotJSON, expectedJSON := mustJSON(t, ctrCiphertext), mustJSON(t, fixtures.AESCTR.Ciphertext); gotJSON != expectedJSON {
		t.Fatalf("expected AES-CTR ciphertext %s, got %s", expectedJSON, gotJSON)
	}
	ctrDecrypted, err := AESCTRDecryptHex(fixtures.AESCTR.Ciphertext, fixtures.AESCTR.Key)
	if err != nil {
		t.Fatal(err)
	}
	if gotJSON, expectedJSON := mustJSON(t, ctrDecrypted), mustJSON(t, fixtures.AESCTR.Decrypted); gotJSON != expectedJSON {
		t.Fatalf("expected AES-CTR plaintext %s, got %s", expectedJSON, gotJSON)
	}

	xChaChaKey, err := HexToBytes(fixtures.XChaCha20.Key)
	if err != nil {
		t.Fatal(err)
	}
	xChaChaCiphertext, err := XChaCha20EncryptHex(fixtures.XChaCha20.Plaintext, xChaChaKey, fixtures.XChaCha20.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if gotJSON, expectedJSON := mustJSON(t, xChaChaCiphertext), mustJSON(t, fixtures.XChaCha20.Ciphertext); gotJSON != expectedJSON {
		t.Fatalf("expected XChaCha20 ciphertext %s, got %s", expectedJSON, gotJSON)
	}
	xChaChaDecrypted, err := XChaCha20DecryptHex(fixtures.XChaCha20.Ciphertext, xChaChaKey)
	if err != nil {
		t.Fatal(err)
	}
	if xChaChaDecrypted != fixtures.XChaCha20.Decrypted {
		t.Fatalf("expected XChaCha20 plaintext %s, got %s", fixtures.XChaCha20.Decrypted, xChaChaDecrypted)
	}

	xChaChaPolyKey, err := HexToBytes(fixtures.XChaCha20Poly1305.Key)
	if err != nil {
		t.Fatal(err)
	}
	xChaChaPolyCiphertext, err := XChaCha20Poly1305EncryptHex(
		fixtures.XChaCha20Poly1305.Plaintext,
		xChaChaPolyKey,
		fixtures.XChaCha20Poly1305.Nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotJSON, expectedJSON := mustJSON(t, xChaChaPolyCiphertext), mustJSON(t, fixtures.XChaCha20Poly1305.Ciphertext); gotJSON != expectedJSON {
		t.Fatalf("expected XChaCha20-Poly1305 ciphertext %s, got %s", expectedJSON, gotJSON)
	}
	xChaChaPolyDecrypted, err := XChaCha20Poly1305DecryptHex(fixtures.XChaCha20Poly1305.Ciphertext, xChaChaPolyKey)
	if err != nil {
		t.Fatal(err)
	}
	if xChaChaPolyDecrypted != fixtures.XChaCha20Poly1305.Decrypted {
		t.Fatalf("expected XChaCha20-Poly1305 plaintext %s, got %s", fixtures.XChaCha20Poly1305.Decrypted, xChaChaPolyDecrypted)
	}
}

func TestMemoFixturesMatchTypeScript(t *testing.T) {
	fixture := loadMemoFixtures(t)
	encodedWalletSource, err := EncodeWalletSource(fixture.WalletSource)
	if err != nil {
		t.Fatal(err)
	}
	if Prefix0x(encodedWalletSource) != fixture.EncodedWalletSource {
		t.Fatalf("expected encoded wallet source %s, got %s", fixture.EncodedWalletSource, Prefix0x(encodedWalletSource))
	}
	viewingPrivateKey, err := HexToBytes(fixture.ViewingPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	v2AnnotationData, err := CreateEncryptedNoteAnnotationDataV2(
		OutputTypeBroadcasterFee,
		fixture.SenderRandom,
		fixture.WalletSource,
		viewingPrivateKey,
		fixture.V2IV,
	)
	if err != nil {
		t.Fatal(err)
	}
	if v2AnnotationData != fixture.V2AnnotationData {
		t.Fatalf("expected V2 annotation data %s, got %s", fixture.V2AnnotationData, v2AnnotationData)
	}
	v3AnnotationData, err := CreateSenderAnnotationEncryptedV3(
		fixture.WalletSource,
		[]int{OutputTypeTransfer, OutputTypeChange},
		viewingPrivateKey,
		fixture.V3Nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	if v3AnnotationData != fixture.V3AnnotationData {
		t.Fatalf("expected V3 annotation data %s, got %s", fixture.V3AnnotationData, v3AnnotationData)
	}
	if encodedMemoText := EncodeMemoText(fixture.MemoText.Input); encodedMemoText != fixture.MemoText.Encoded {
		t.Fatalf("expected encoded memo %s, got %s", fixture.MemoText.Encoded, encodedMemoText)
	}
	decodedMemoText, err := DecodeMemoText(fixture.MemoText.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decodedMemoText != fixture.MemoText.Input {
		t.Fatalf("expected decoded memo %s, got %s", fixture.MemoText.Input, decodedMemoText)
	}
	decryptedV2Annotation, err := DecryptNoteAnnotationDataV2(fixture.V2AnnotationData, viewingPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if decryptedV2Annotation.OutputType != OutputTypeBroadcasterFee {
		t.Fatalf("expected V2 annotation output type %d, got %d", OutputTypeBroadcasterFee, decryptedV2Annotation.OutputType)
	}
	if decryptedV2Annotation.SenderRandom != fixture.SenderRandom {
		t.Fatalf("expected V2 annotation sender random %s, got %s", fixture.SenderRandom, decryptedV2Annotation.SenderRandom)
	}
	if !strings.EqualFold(decryptedV2Annotation.WalletSource, fixture.WalletSource) {
		t.Fatalf("expected V2 annotation wallet source %s, got %s", fixture.WalletSource, decryptedV2Annotation.WalletSource)
	}
	decryptedV3Annotation, err := DecryptSenderAnnotationV3(fixture.V3AnnotationData, viewingPrivateKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decryptedV3Annotation.OutputType != OutputTypeTransfer {
		t.Fatalf("expected V3 annotation output type %d, got %d", OutputTypeTransfer, decryptedV3Annotation.OutputType)
	}
	if !strings.EqualFold(decryptedV3Annotation.WalletSource, fixture.WalletSource) {
		t.Fatalf("expected V3 annotation wallet source %s, got %s", fixture.WalletSource, decryptedV3Annotation.WalletSource)
	}
}

func TestWalletSourceValidationMatchesTypeScript(t *testing.T) {
	normalized, err := NormalizeWalletSource("New Wallet")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "new wallet" {
		t.Fatalf("expected lower-case wallet source, got %s", normalized)
	}
	if err := ValidateWalletSource(""); err == nil || !strings.Contains(err.Error(), "valid wallet source") {
		t.Fatalf("expected empty wallet source to fail, got %v", err)
	}
	if err := ValidateWalletSource("1234567890abcdefg"); err == nil || !strings.Contains(err.Error(), "less than 16") {
		t.Fatalf("expected long wallet source to fail, got %v", err)
	}
	if err := ValidateWalletSource("bad!"); err == nil || !strings.Contains(err.Error(), "Invalid character") {
		t.Fatalf("expected invalid wallet source character to fail, got %v", err)
	}
}

func TestTransactNoteFixturesMatchTypeScript(t *testing.T) {
	fixture := loadTransactNoteFixtures(t)
	sharedKey, err := HexToBytes(fixture.Inputs.SharedKey)
	if err != nil {
		t.Fatal(err)
	}
	viewingPrivateKey, err := HexToBytes(fixture.Inputs.ViewingPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	inputs := TransactNoteEncryptionInputs{
		ReceiverMasterPublicKey: mustDec(t, fixture.Inputs.ReceiverMasterPublicKey),
		SenderMasterPublicKey:   mustDec(t, fixture.Inputs.SenderMasterPublicKey),
		Random:                  fixture.Inputs.Random,
		Value:                   mustDec(t, fixture.Inputs.Value),
		TokenData:               fixture.Inputs.TokenData,
		SenderRandom:            fixture.Inputs.SenderRandom,
		SharedKey:               sharedKey,
		ViewingPrivateKey:       viewingPrivateKey,
		OutputType:              fixture.Inputs.OutputType,
		WalletSource:            fixture.Inputs.WalletSource,
		MemoText:                fixture.Inputs.MemoText,
	}
	v2, err := EncryptTransactNoteV2(inputs, fixture.Inputs.NoteCiphertextV2IV, fixture.Inputs.AnnotationV2IV)
	if err != nil {
		t.Fatal(err)
	}
	if gotJSON, expectedJSON := mustJSON(t, v2), mustJSON(t, fixture.V2); gotJSON != expectedJSON {
		t.Fatalf("expected V2 transact note encryption %s, got %s", expectedJSON, gotJSON)
	}
	v3, err := EncryptTransactNoteV3(
		inputs,
		fixture.Inputs.NoteCiphertextV3Nonce,
		fixture.Inputs.AnnotationV3Nonce,
		fixture.Inputs.OrderedOutputTypes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotJSON, expectedJSON := mustJSON(t, v3), mustJSON(t, fixture.V3); gotJSON != expectedJSON {
		t.Fatalf("expected V3 transact note encryption %s, got %s", expectedJSON, gotJSON)
	}

	receiverViewingPublicKey, err := HexToBytes(fixture.Inputs.ReceiverViewingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	senderViewingPublicKey, err := HexToBytes(fixture.Inputs.SenderViewingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	blindedSenderViewingKey, err := HexToBytes(fixture.NoteBlinding.BlindedSenderViewingKey)
	if err != nil {
		t.Fatal(err)
	}
	blindedReceiverViewingKey, err := HexToBytes(fixture.NoteBlinding.BlindedReceiverViewingKey)
	if err != nil {
		t.Fatal(err)
	}
	receiverAddressData := TransactNoteAddressData{
		MasterPublicKey:  inputs.ReceiverMasterPublicKey,
		ViewingPublicKey: receiverViewingPublicKey,
	}
	senderAddressData := TransactNoteAddressData{
		MasterPublicKey:  inputs.SenderMasterPublicKey,
		ViewingPublicKey: senderViewingPublicKey,
	}
	v2Sent, err := DecryptTransactNoteV2(
		senderAddressData,
		fixture.V2.NoteCiphertext,
		sharedKey,
		fixture.V2.NoteMemo,
		fixture.V2.AnnotationData,
		viewingPrivateKey,
		blindedReceiverViewingKey,
		blindedSenderViewingKey,
		true,
		false,
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertDecryptedTransactNote(t, v2Sent, fixture.Decrypted.V2Sent)
	v2Received, err := DecryptTransactNoteV2(
		receiverAddressData,
		fixture.V2.NoteCiphertext,
		sharedKey,
		fixture.V2.NoteMemo,
		fixture.V2.AnnotationData,
		viewingPrivateKey,
		blindedReceiverViewingKey,
		blindedSenderViewingKey,
		false,
		false,
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertDecryptedTransactNote(t, v2Received, fixture.Decrypted.V2Received)
	v3Sent, err := DecryptTransactNoteV3(
		senderAddressData,
		fixture.V3.NoteCiphertext,
		sharedKey,
		fixture.V3.AnnotationData,
		viewingPrivateKey,
		blindedReceiverViewingKey,
		blindedSenderViewingKey,
		true,
		false,
		nil,
		nil,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertDecryptedTransactNote(t, v3Sent, fixture.Decrypted.V3Sent)
	v3Received, err := DecryptTransactNoteV3(
		receiverAddressData,
		fixture.V3.NoteCiphertext,
		sharedKey,
		fixture.V3.AnnotationData,
		viewingPrivateKey,
		blindedReceiverViewingKey,
		blindedSenderViewingKey,
		false,
		false,
		nil,
		nil,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertDecryptedTransactNote(t, v3Received, fixture.Decrypted.V3Received)
}

func assertDecryptedTransactNote(t *testing.T, got DecryptedTransactNote, expected decryptedTransactNoteFixture) {
	t.Helper()
	assertBigIntString(t, got.ReceiverAddressData.MasterPublicKey, expected.ReceiverMasterPublicKey, "receiverMasterPublicKey")
	if got := BytesToHex(got.ReceiverAddressData.ViewingPublicKey, false); got != expected.ReceiverViewingPublicKey {
		t.Fatalf("expected receiver viewing public key %s, got %s", expected.ReceiverViewingPublicKey, got)
	}
	if expected.SenderMasterPublicKey == "" {
		if got.SenderAddressData != nil {
			t.Fatalf("expected no sender address data, got %+v", got.SenderAddressData)
		}
	} else {
		if got.SenderAddressData == nil {
			t.Fatalf("expected sender address data")
		}
		assertBigIntString(t, got.SenderAddressData.MasterPublicKey, expected.SenderMasterPublicKey, "senderMasterPublicKey")
		if got := BytesToHex(got.SenderAddressData.ViewingPublicKey, false); got != expected.SenderViewingPublicKey {
			t.Fatalf("expected sender viewing public key %s, got %s", expected.SenderViewingPublicKey, got)
		}
	}
	if got.TokenHash != expected.TokenHash {
		t.Fatalf("expected token hash %s, got %s", expected.TokenHash, got.TokenHash)
	}
	if gotJSON, expectedJSON := mustJSON(t, got.TokenData), mustJSON(t, expected.TokenData); gotJSON != expectedJSON {
		t.Fatalf("expected token data %s, got %s", expectedJSON, gotJSON)
	}
	if got.Random != expected.Random {
		t.Fatalf("expected random %s, got %s", expected.Random, got.Random)
	}
	assertBigIntString(t, got.Value, expected.Value, "value")
	assertBigIntString(t, got.NotePublicKey, expected.NotePublicKey, "notePublicKey")
	assertBigIntString(t, got.Hash, expected.Hash, "hash")
	if expected.OutputType == nil {
		if got.OutputType != nil {
			t.Fatalf("expected no output type, got %d", *got.OutputType)
		}
	} else {
		if got.OutputType == nil {
			t.Fatalf("expected output type %d", *expected.OutputType)
		}
		if *got.OutputType != *expected.OutputType {
			t.Fatalf("expected output type %d, got %d", *expected.OutputType, *got.OutputType)
		}
	}
	if got.WalletSource != expected.WalletSource {
		t.Fatalf("expected wallet source %s, got %s", expected.WalletSource, got.WalletSource)
	}
	if got.SenderRandom != expected.SenderRandom {
		t.Fatalf("expected sender random %s, got %s", expected.SenderRandom, got.SenderRandom)
	}
	if got.MemoText != expected.MemoText {
		t.Fatalf("expected memo text %s, got %s", expected.MemoText, got.MemoText)
	}
}

func mustDec(t *testing.T, value string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid decimal %s", value)
	}
	return n
}

type exportedFixtures struct {
	CryptoFixtures       cryptoFixtureSet       `json:"cryptoFixtures"`
	EncryptionFixtures   encryptionFixtureSet   `json:"encryptionFixtures"`
	MemoFixtures         memoFixtureSet         `json:"memoFixtures"`
	TransactNoteFixtures transactNoteFixtureSet `json:"transactNoteFixtures"`
}

type cryptoFixtureSet struct {
	PoseidonVectors []poseidonFixture  `json:"poseidonVectors"`
	KeyVector       keyFixture         `json:"keyVector"`
	TokenVectors    []tokenFixture     `json:"tokenVectors"`
	POIReference    poiCryptoReference `json:"poiReference"`
}

type poseidonFixture struct {
	Name   string   `json:"name"`
	Inputs []string `json:"inputs"`
	Output string   `json:"output"`
}

type keyFixture struct {
	PrivateKey                string                    `json:"privateKey"`
	PoseidonMessage           string                    `json:"poseidonMessage"`
	SpendingPublicKey         [2]string                 `json:"spendingPublicKey"`
	PoseidonSignature         poseidonSignatureJSON     `json:"poseidonSignature"`
	PoseidonSignatureVerified bool                      `json:"poseidonSignatureVerified"`
	PublicViewingKey          string                    `json:"publicViewingKey"`
	PrivateScalar             string                    `json:"privateScalar"`
	SharedSymmetricKey        string                    `json:"sharedSymmetricKey"`
	ED25519Message            string                    `json:"ed25519Message"`
	ED25519Signature          string                    `json:"ed25519Signature"`
	ED25519SignatureVerified  bool                      `json:"ed25519SignatureVerified"`
	NoteBlinding              noteBlindingFixture       `json:"noteBlinding"`
	LegacyNoteBlinding        legacyNoteBlindingFixture `json:"legacyNoteBlinding"`
}

type poseidonSignatureJSON struct {
	R8 [2]string `json:"R8"`
	S  string    `json:"S"`
}

type noteBlindingFixture struct {
	ReceiverPrivateKey        string `json:"receiverPrivateKey"`
	ReceiverViewingPublicKey  string `json:"receiverViewingPublicKey"`
	SharedRandom              string `json:"sharedRandom"`
	SenderRandom              string `json:"senderRandom"`
	BlindedSenderViewingKey   string `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string `json:"blindedReceiverViewingKey"`
	UnblindedSenderViewingKey string `json:"unblindedSenderViewingKey"`
}

type legacyNoteBlindingFixture struct {
	ReceiverPrivateKey          string `json:"receiverPrivateKey"`
	ReceiverViewingPublicKey    string `json:"receiverViewingPublicKey"`
	SharedRandom                string `json:"sharedRandom"`
	SenderRandom                string `json:"senderRandom"`
	SharedSymmetricKey          string `json:"sharedSymmetricKey"`
	BlindedSenderViewingKey     string `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey   string `json:"blindedReceiverViewingKey"`
	UnblindedSenderViewingKey   string `json:"unblindedSenderViewingKey"`
	UnblindedReceiverViewingKey string `json:"unblindedReceiverViewingKey"`
}

type tokenFixture struct {
	Name          string    `json:"name"`
	TokenData     TokenData `json:"tokenData"`
	TokenHash     string    `json:"tokenHash"`
	NotePublicKey string    `json:"notePublicKey"`
	Value         string    `json:"value"`
	NoteHash      string    `json:"noteHash"`
}

type poiCryptoReference struct {
	SpendingPublicKey   [2]string `json:"spendingPublicKey"`
	NullifyingKey       string    `json:"nullifyingKey"`
	Random              string    `json:"random"`
	Token               string    `json:"token"`
	Value               string    `json:"value"`
	NotePosition        uint64    `json:"notePosition"`
	GlobalTreePosition  string    `json:"globalTreePosition"`
	MasterPublicKey     string    `json:"masterPublicKey"`
	NotePublicKey       string    `json:"notePublicKey"`
	ShieldCommitment    string    `json:"shieldCommitment"`
	ShieldCommitmentHex string    `json:"shieldCommitmentHex"`
	BlindedCommitment   string    `json:"blindedCommitment"`
	Nullifier           string    `json:"nullifier"`
	NullifierHex        string    `json:"nullifierHex"`
	TokenDataHashERC20  string    `json:"tokenDataHashERC20"`
}

type encryptionFixtureSet struct {
	AESGCM            aesGCMFixture  `json:"aesGCM"`
	AESCTR            aesCTRFixture  `json:"aesCTR"`
	XChaCha20         xChaChaFixture `json:"xChaCha20"`
	XChaCha20Poly1305 xChaChaFixture `json:"xChaCha20Poly1305"`
}

type aesGCMFixture struct {
	Key        string        `json:"key"`
	IV         string        `json:"iv"`
	Plaintext  []string      `json:"plaintext"`
	Ciphertext CiphertextGCM `json:"ciphertext"`
	Decrypted  []string      `json:"decrypted"`
}

type aesCTRFixture struct {
	Key        string        `json:"key"`
	IV         string        `json:"iv"`
	Plaintext  []string      `json:"plaintext"`
	Ciphertext CiphertextCTR `json:"ciphertext"`
	Decrypted  []string      `json:"decrypted"`
}

type xChaChaFixture struct {
	Key        string            `json:"key"`
	Nonce      string            `json:"nonce"`
	Plaintext  string            `json:"plaintext"`
	Ciphertext CiphertextXChaCha `json:"ciphertext"`
	Decrypted  string            `json:"decrypted"`
}

type memoFixtureSet struct {
	WalletSource        string          `json:"walletSource"`
	EncodedWalletSource string          `json:"encodedWalletSource"`
	SenderRandom        string          `json:"senderRandom"`
	ViewingPrivateKey   string          `json:"viewingPrivateKey"`
	V2IV                string          `json:"v2IV"`
	V2AnnotationData    string          `json:"v2AnnotationData"`
	V3Nonce             string          `json:"v3Nonce"`
	V3AnnotationData    string          `json:"v3AnnotationData"`
	MemoText            memoTextFixture `json:"memoText"`
}

type memoTextFixture struct {
	Input   string `json:"input"`
	Encoded string `json:"encoded"`
}

type transactNoteFixtureSet struct {
	Inputs       transactNoteInputsFixture     `json:"inputs"`
	V2           TransactNoteV2Encryption      `json:"v2"`
	V3           TransactNoteV3Encryption      `json:"v3"`
	NoteBlinding transactNoteBlindingFixture   `json:"noteBlinding"`
	Decrypted    transactNoteDecryptedFixtures `json:"decrypted"`
}

type transactNoteInputsFixture struct {
	ReceiverMasterPublicKey  string    `json:"receiverMasterPublicKey"`
	SenderMasterPublicKey    string    `json:"senderMasterPublicKey"`
	ReceiverViewingPublicKey string    `json:"receiverViewingPublicKey"`
	SenderViewingPublicKey   string    `json:"senderViewingPublicKey"`
	TokenData                TokenData `json:"tokenData"`
	Random                   string    `json:"random"`
	Value                    string    `json:"value"`
	SenderRandom             string    `json:"senderRandom"`
	SharedKey                string    `json:"sharedKey"`
	ViewingPrivateKey        string    `json:"viewingPrivateKey"`
	OutputType               int       `json:"outputType"`
	WalletSource             string    `json:"walletSource"`
	MemoText                 string    `json:"memoText"`
	NoteCiphertextV2IV       string    `json:"noteCiphertextV2IV"`
	AnnotationV2IV           string    `json:"annotationV2IV"`
	NoteCiphertextV3Nonce    string    `json:"noteCiphertextV3Nonce"`
	AnnotationV3Nonce        string    `json:"annotationV3Nonce"`
	OrderedOutputTypes       []int     `json:"orderedOutputTypes"`
}

type transactNoteBlindingFixture struct {
	BlindedSenderViewingKey   string `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string `json:"blindedReceiverViewingKey"`
}

type transactNoteDecryptedFixtures struct {
	V2Sent     decryptedTransactNoteFixture `json:"v2Sent"`
	V2Received decryptedTransactNoteFixture `json:"v2Received"`
	V3Sent     decryptedTransactNoteFixture `json:"v3Sent"`
	V3Received decryptedTransactNoteFixture `json:"v3Received"`
}

type decryptedTransactNoteFixture struct {
	ReceiverMasterPublicKey  string    `json:"receiverMasterPublicKey"`
	ReceiverViewingPublicKey string    `json:"receiverViewingPublicKey"`
	SenderMasterPublicKey    string    `json:"senderMasterPublicKey"`
	SenderViewingPublicKey   string    `json:"senderViewingPublicKey"`
	TokenHash                string    `json:"tokenHash"`
	TokenData                TokenData `json:"tokenData"`
	Random                   string    `json:"random"`
	Value                    string    `json:"value"`
	NotePublicKey            string    `json:"notePublicKey"`
	Hash                     string    `json:"hash"`
	OutputType               *int      `json:"outputType"`
	WalletSource             string    `json:"walletSource"`
	SenderRandom             string    `json:"senderRandom"`
	MemoText                 string    `json:"memoText"`
}

func loadCryptoFixtures(t *testing.T) cryptoFixtureSet {
	t.Helper()
	return loadExportedFixtures(t).CryptoFixtures
}

func loadEncryptionFixtures(t *testing.T) encryptionFixtureSet {
	t.Helper()
	return loadExportedFixtures(t).EncryptionFixtures
}

func loadMemoFixtures(t *testing.T) memoFixtureSet {
	t.Helper()
	return loadExportedFixtures(t).MemoFixtures
}

func loadTransactNoteFixtures(t *testing.T) transactNoteFixtureSet {
	t.Helper()
	return loadExportedFixtures(t).TransactNoteFixtures
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

func assertBigIntString(t *testing.T, got *big.Int, expected string, label string) {
	t.Helper()
	if got.String() != expected {
		t.Fatalf("expected %s %s, got %s", label, expected, got)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
