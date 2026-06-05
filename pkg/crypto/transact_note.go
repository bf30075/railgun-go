package railcrypto

import (
	"fmt"
	"math/big"
	"strings"
)

const (
	TXIDVersionV2PoseidonMerkle = "V2_PoseidonMerkle"
	TXIDVersionV3PoseidonMerkle = "V3_PoseidonMerkle"
	erc20TokenHashPrefix        = "000000000000000000000000"
)

type TransactNoteV2Encryption struct {
	NoteCiphertext CiphertextGCM `json:"noteCiphertext"`
	NoteMemo       string        `json:"noteMemo"`
	AnnotationData string        `json:"annotationData"`
}

type TransactNoteV3Encryption struct {
	NoteCiphertext CiphertextXChaCha `json:"noteCiphertext"`
	AnnotationData string            `json:"annotationData"`
}

type TransactNoteEncryptionInputs struct {
	ReceiverMasterPublicKey *big.Int
	SenderMasterPublicKey   *big.Int
	Random                  string
	Value                   *big.Int
	TokenData               TokenData
	SenderRandom            string
	SharedKey               []byte
	ViewingPrivateKey       []byte
	OutputType              int
	WalletSource            string
	MemoText                string
}

type TransactNoteAddressData struct {
	MasterPublicKey  *big.Int
	ViewingPublicKey []byte
}

type DecryptedTransactNote struct {
	ReceiverAddressData TransactNoteAddressData
	SenderAddressData   *TransactNoteAddressData
	TokenHash           string
	TokenData           TokenData
	Random              string
	Value               *big.Int
	NotePublicKey       *big.Int
	Hash                *big.Int
	OutputType          *int
	WalletSource        string
	SenderRandom        string
	MemoText            string
	BlockNumber         *uint64
}

func DecryptTransactNoteV2(
	currentWalletAddressData TransactNoteAddressData,
	noteCiphertext CiphertextGCM,
	sharedKey []byte,
	memoV2 string,
	annotationData string,
	viewingPrivateKey []byte,
	blindedReceiverViewingKey []byte,
	blindedSenderViewingKey []byte,
	isSentNote bool,
	isLegacyDecryption bool,
	tokenDataByHash map[string]TokenData,
	blockNumber *uint64,
) (DecryptedTransactNote, error) {
	fullCiphertext := CiphertextGCM{
		IV:   noteCiphertext.IV,
		Tag:  noteCiphertext.Tag,
		Data: append(append([]string{}, noteCiphertext.Data...), Strip0x(memoV2)),
	}
	decryptedCiphertext, err := AESGCMDecryptHex(fullCiphertext, BytesToHex(sharedKey, false))
	if err != nil {
		return DecryptedTransactNote{}, err
	}
	values, err := decryptedValuesNoteCiphertextV2(decryptedCiphertext, tokenDataByHash)
	if err != nil {
		return DecryptedTransactNote{}, err
	}
	var outputType *int
	walletSource := ""
	senderRandom := ""
	if isSentNote {
		noteAnnotationData, err := DecryptNoteAnnotationDataV2(annotationData, viewingPrivateKey)
		if err != nil {
			return DecryptedTransactNote{}, err
		}
		outputType = intPtr(noteAnnotationData.OutputType)
		walletSource = noteAnnotationData.WalletSource
		senderRandom = noteAnnotationData.SenderRandom
	}
	return noteFromDecryptedValues(
		currentWalletAddressData,
		outputType,
		walletSource,
		blindedReceiverViewingKey,
		blindedSenderViewingKey,
		senderRandom,
		isSentNote,
		isLegacyDecryption,
		blockNumber,
		values,
	)
}

func DecryptTransactNoteV3(
	currentWalletAddressData TransactNoteAddressData,
	noteCiphertext CiphertextXChaCha,
	sharedKey []byte,
	annotationData string,
	viewingPrivateKey []byte,
	blindedReceiverViewingKey []byte,
	blindedSenderViewingKey []byte,
	isSentNote bool,
	isLegacyDecryption bool,
	tokenDataByHash map[string]TokenData,
	blockNumber *uint64,
	transactCommitmentBatchIndex int,
) (DecryptedTransactNote, error) {
	decryptedCiphertext, err := XChaCha20Poly1305DecryptHex(noteCiphertext, sharedKey)
	if err != nil {
		return DecryptedTransactNote{}, err
	}
	values, err := decryptedValuesNoteCiphertextV3(decryptedCiphertext, tokenDataByHash)
	if err != nil {
		return DecryptedTransactNote{}, err
	}
	var outputType *int
	walletSource := ""
	if isSentNote {
		senderAnnotation, err := DecryptSenderAnnotationV3(annotationData, viewingPrivateKey, transactCommitmentBatchIndex)
		if err != nil {
			return DecryptedTransactNote{}, err
		}
		outputType = intPtr(senderAnnotation.OutputType)
		walletSource = senderAnnotation.WalletSource
	}
	return noteFromDecryptedValues(
		currentWalletAddressData,
		outputType,
		walletSource,
		blindedReceiverViewingKey,
		blindedSenderViewingKey,
		values.SenderRandom,
		isSentNote,
		isLegacyDecryption,
		blockNumber,
		values,
	)
}

func GetDecodedMasterPublicKey(currentWalletMasterPublicKey *big.Int, encodedMasterPublicKey *big.Int, senderRandom string, isLegacyDecryption bool) *big.Int {
	if isLegacyDecryption || (senderRandom != "" && senderRandom != MemoSenderRandomNull) {
		return new(big.Int).Set(encodedMasterPublicKey)
	}
	return new(big.Int).Xor(currentWalletMasterPublicKey, encodedMasterPublicKey)
}

func GetEncodedMasterPublicKey(senderRandom string, receiverMasterPublicKey *big.Int, senderMasterPublicKey *big.Int) *big.Int {
	return encodedMasterPublicKey(senderRandom, receiverMasterPublicKey, senderMasterPublicKey)
}

func EncryptTransactNoteV2(inputs TransactNoteEncryptionInputs, noteCiphertextIV string, annotationIV string) (TransactNoteV2Encryption, error) {
	fields, err := formatTransactNoteEncryptionFields(inputs)
	if err != nil {
		return TransactNoteV2Encryption{}, err
	}
	memoText := EncodeMemoText(inputs.MemoText)
	ciphertext, err := AESGCMEncryptHex(
		[]string{
			fields.EncodedMasterPublicKey,
			fields.TokenHash,
			fields.Random + fields.Value,
			memoText,
		},
		BytesToHex(inputs.SharedKey, false),
		noteCiphertextIV,
	)
	if err != nil {
		return TransactNoteV2Encryption{}, err
	}
	if len(ciphertext.Data) != 4 {
		return TransactNoteV2Encryption{}, fmt.Errorf("expected 4 ciphertext data fields, got %d", len(ciphertext.Data))
	}
	noteMemo := ciphertext.Data[3]
	ciphertext.Data = append([]string(nil), ciphertext.Data[:3]...)
	annotationData, err := CreateEncryptedNoteAnnotationDataV2(
		inputs.OutputType,
		inputs.SenderRandom,
		inputs.WalletSource,
		inputs.ViewingPrivateKey,
		annotationIV,
	)
	if err != nil {
		return TransactNoteV2Encryption{}, err
	}
	return TransactNoteV2Encryption{
		NoteCiphertext: ciphertext,
		NoteMemo:       noteMemo,
		AnnotationData: annotationData,
	}, nil
}

func EncryptTransactNoteV3(inputs TransactNoteEncryptionInputs, noteCiphertextNonce string, annotationNonce string, orderedOutputTypes []int) (TransactNoteV3Encryption, error) {
	ciphertext, err := EncryptTransactNoteV3Ciphertext(inputs, noteCiphertextNonce)
	if err != nil {
		return TransactNoteV3Encryption{}, err
	}
	annotationData, err := CreateSenderAnnotationEncryptedV3(
		inputs.WalletSource,
		orderedOutputTypes,
		inputs.ViewingPrivateKey,
		annotationNonce,
	)
	if err != nil {
		return TransactNoteV3Encryption{}, err
	}
	return TransactNoteV3Encryption{
		NoteCiphertext: ciphertext,
		AnnotationData: annotationData,
	}, nil
}

func EncryptTransactNoteV3Ciphertext(inputs TransactNoteEncryptionInputs, noteCiphertextNonce string) (CiphertextXChaCha, error) {
	fields, err := formatTransactNoteEncryptionFields(inputs)
	if err != nil {
		return CiphertextXChaCha{}, err
	}
	senderRandom, err := FormatHexToByteLength(inputs.SenderRandom, 15, false)
	if err != nil {
		return CiphertextXChaCha{}, fmt.Errorf("sender random: %w", err)
	}
	memoText := EncodeMemoText(inputs.MemoText)
	ciphertext, err := XChaCha20Poly1305EncryptHex(
		fields.EncodedMasterPublicKey+fields.Random+fields.Value+fields.TokenHash+senderRandom+memoText,
		inputs.SharedKey,
		noteCiphertextNonce,
	)
	if err != nil {
		return CiphertextXChaCha{}, err
	}
	return ciphertext, nil
}

type transactNoteEncryptionFields struct {
	EncodedMasterPublicKey string
	TokenHash              string
	Value                  string
	Random                 string
}

func formatTransactNoteEncryptionFields(inputs TransactNoteEncryptionInputs) (transactNoteEncryptionFields, error) {
	if inputs.ReceiverMasterPublicKey == nil {
		return transactNoteEncryptionFields{}, fmt.Errorf("receiver master public key is required")
	}
	if inputs.SenderMasterPublicKey == nil {
		return transactNoteEncryptionFields{}, fmt.Errorf("sender master public key is required")
	}
	if inputs.Value == nil {
		return transactNoteEncryptionFields{}, fmt.Errorf("value is required")
	}
	tokenHash, err := TokenDataHash(inputs.TokenData)
	if err != nil {
		return transactNoteEncryptionFields{}, err
	}
	random, err := FormatHexToByteLength(inputs.Random, 16, false)
	if err != nil {
		return transactNoteEncryptionFields{}, fmt.Errorf("random: %w", err)
	}
	value, err := BigIntToHex(inputs.Value, 16, false)
	if err != nil {
		return transactNoteEncryptionFields{}, err
	}
	encodedMasterPublicKey := encodedMasterPublicKey(
		inputs.SenderRandom,
		inputs.ReceiverMasterPublicKey,
		inputs.SenderMasterPublicKey,
	)
	encodedMasterPublicKeyHex, err := BigIntToHex(encodedMasterPublicKey, 32, false)
	if err != nil {
		return transactNoteEncryptionFields{}, err
	}
	return transactNoteEncryptionFields{
		EncodedMasterPublicKey: encodedMasterPublicKeyHex,
		TokenHash:              tokenHash,
		Value:                  value,
		Random:                 random,
	}, nil
}

func encodedMasterPublicKey(senderRandom string, receiverMasterPublicKey *big.Int, senderMasterPublicKey *big.Int) *big.Int {
	if senderRandom != "" && senderRandom != MemoSenderRandomNull {
		return new(big.Int).Set(receiverMasterPublicKey)
	}
	return new(big.Int).Xor(receiverMasterPublicKey, senderMasterPublicKey)
}

type transactNoteDecryptedValues struct {
	Random       string
	Value        *big.Int
	MemoText     string
	TokenHash    string
	TokenData    TokenData
	EncodedMPK   *big.Int
	SenderRandom string
}

func decryptedValuesNoteCiphertextV2(decryptedCiphertext []string, tokenDataByHash map[string]TokenData) (transactNoteDecryptedValues, error) {
	if len(decryptedCiphertext) < 4 {
		return transactNoteDecryptedValues{}, fmt.Errorf("expected at least 4 decrypted ciphertext fields, got %d", len(decryptedCiphertext))
	}
	if len(decryptedCiphertext[2]) < 64 {
		return transactNoteDecryptedValues{}, fmt.Errorf("invalid random/value field length")
	}
	random := decryptedCiphertext[2][:32]
	value, err := HexToBigInt(decryptedCiphertext[2][32:64])
	if err != nil {
		return transactNoteDecryptedValues{}, err
	}
	tokenHash, err := FormatHexToByteLength(decryptedCiphertext[1], 32, false)
	if err != nil {
		return transactNoteDecryptedValues{}, err
	}
	memoText, err := DecodeMemoText(strings.Join(decryptedCiphertext[3:], ""))
	if err != nil {
		return transactNoteDecryptedValues{}, err
	}
	tokenData, err := TokenDataFromHash(tokenHash, tokenDataByHash)
	if err != nil {
		return transactNoteDecryptedValues{}, err
	}
	encodedMPK, err := HexToBigInt(decryptedCiphertext[0])
	if err != nil {
		return transactNoteDecryptedValues{}, err
	}
	return transactNoteDecryptedValues{
		Random:     random,
		Value:      value,
		MemoText:   memoText,
		TokenHash:  tokenHash,
		TokenData:  tokenData,
		EncodedMPK: encodedMPK,
	}, nil
}

func decryptedValuesNoteCiphertextV3(decryptedCiphertext string, tokenDataByHash map[string]TokenData) (transactNoteDecryptedValues, error) {
	if len(decryptedCiphertext) < 222 {
		return transactNoteDecryptedValues{}, fmt.Errorf("invalid V3 decrypted ciphertext length")
	}
	encodedMPK, err := HexToBigInt(decryptedCiphertext[:64])
	if err != nil {
		return transactNoteDecryptedValues{}, err
	}
	random := decryptedCiphertext[64:96]
	value, err := HexToBigInt(decryptedCiphertext[96:128])
	if err != nil {
		return transactNoteDecryptedValues{}, err
	}
	tokenHash, err := FormatHexToByteLength(decryptedCiphertext[128:192], 32, false)
	if err != nil {
		return transactNoteDecryptedValues{}, err
	}
	tokenData, err := TokenDataFromHash(tokenHash, tokenDataByHash)
	if err != nil {
		return transactNoteDecryptedValues{}, err
	}
	senderRandom := decryptedCiphertext[192:222]
	memoText := ""
	if len(decryptedCiphertext) > 222 {
		memoText, err = DecodeMemoText(decryptedCiphertext[222:])
		if err != nil {
			return transactNoteDecryptedValues{}, err
		}
	}
	return transactNoteDecryptedValues{
		Random:       random,
		Value:        value,
		MemoText:     memoText,
		TokenHash:    tokenHash,
		TokenData:    tokenData,
		EncodedMPK:   encodedMPK,
		SenderRandom: senderRandom,
	}, nil
}

func TokenDataFromHash(tokenHash string, tokenDataByHash map[string]TokenData) (TokenData, error) {
	formatted, err := FormatHexToByteLength(tokenHash, 32, false)
	if err != nil {
		return TokenData{}, err
	}
	if strings.HasPrefix(formatted, erc20TokenHashPrefix) {
		return TokenDataERC20(formatted)
	}
	if tokenDataByHash != nil {
		if tokenData, ok := tokenDataByHash[formatted]; ok {
			return tokenData, nil
		}
		if tokenData, ok := tokenDataByHash[Prefix0x(formatted)]; ok {
			return tokenData, nil
		}
	}
	return TokenData{}, fmt.Errorf("token data not found for hash %s", formatted)
}

func noteFromDecryptedValues(
	currentWalletAddressData TransactNoteAddressData,
	outputType *int,
	walletSource string,
	blindedReceiverViewingKey []byte,
	blindedSenderViewingKey []byte,
	senderRandom string,
	isSentNote bool,
	isLegacyDecryption bool,
	blockNumber *uint64,
	values transactNoteDecryptedValues,
) (DecryptedTransactNote, error) {
	if isSentNote {
		receiverViewingPublicKey, err := unblindViewingPublicKey(values.Random, blindedReceiverViewingKey, senderRandom, isLegacyDecryption)
		if err != nil {
			return DecryptedTransactNote{}, err
		}
		receiverAddressData := TransactNoteAddressData{
			MasterPublicKey:  GetDecodedMasterPublicKey(currentWalletAddressData.MasterPublicKey, values.EncodedMPK, senderRandom, isLegacyDecryption),
			ViewingPublicKey: receiverViewingPublicKey,
		}
		return buildDecryptedTransactNote(
			receiverAddressData,
			&currentWalletAddressData,
			outputType,
			walletSource,
			senderRandom,
			blockNumber,
			values,
		)
	}

	var senderAddressData *TransactNoteAddressData
	if values.EncodedMPK.Cmp(currentWalletAddressData.MasterPublicKey) != 0 {
		senderViewingPublicKey, err := unblindViewingPublicKey(values.Random, blindedSenderViewingKey, MemoSenderRandomNull, isLegacyDecryption)
		if err != nil {
			return DecryptedTransactNote{}, err
		}
		senderAddressData = &TransactNoteAddressData{
			MasterPublicKey:  GetDecodedMasterPublicKey(currentWalletAddressData.MasterPublicKey, values.EncodedMPK, MemoSenderRandomNull, isLegacyDecryption),
			ViewingPublicKey: senderViewingPublicKey,
		}
	}
	return buildDecryptedTransactNote(
		currentWalletAddressData,
		senderAddressData,
		outputType,
		walletSource,
		senderRandom,
		blockNumber,
		values,
	)
}

func buildDecryptedTransactNote(
	receiverAddressData TransactNoteAddressData,
	senderAddressData *TransactNoteAddressData,
	outputType *int,
	walletSource string,
	senderRandom string,
	blockNumber *uint64,
	values transactNoteDecryptedValues,
) (DecryptedTransactNote, error) {
	notePublicKey, err := NotePublicKey(receiverAddressData.MasterPublicKey, values.Random)
	if err != nil {
		return DecryptedTransactNote{}, err
	}
	hash, err := NoteHash(notePublicKey, values.TokenHash, values.Value)
	if err != nil {
		return DecryptedTransactNote{}, err
	}
	return DecryptedTransactNote{
		ReceiverAddressData: cloneAddressData(receiverAddressData),
		SenderAddressData:   cloneAddressDataPtr(senderAddressData),
		TokenHash:           values.TokenHash,
		TokenData:           values.TokenData,
		Random:              values.Random,
		Value:               new(big.Int).Set(values.Value),
		NotePublicKey:       notePublicKey,
		Hash:                hash,
		OutputType:          cloneIntPtr(outputType),
		WalletSource:        walletSource,
		SenderRandom:        senderRandom,
		MemoText:            values.MemoText,
		BlockNumber:         cloneUint64Ptr(blockNumber),
	}, nil
}

func unblindViewingPublicKey(random string, blindedViewingPublicKey []byte, senderRandom string, isLegacyDecryption bool) ([]byte, error) {
	if len(blindedViewingPublicKey) == 0 || senderRandom == "" {
		return nil, nil
	}
	if isLegacyDecryption {
		return UnblindNoteKeyLegacy(blindedViewingPublicKey, random, senderRandom)
	}
	return UnblindNoteKey(blindedViewingPublicKey, random, senderRandom)
}

func cloneAddressData(value TransactNoteAddressData) TransactNoteAddressData {
	return TransactNoteAddressData{
		MasterPublicKey:  new(big.Int).Set(value.MasterPublicKey),
		ViewingPublicKey: cloneBytes(value.ViewingPublicKey),
	}
}

func cloneAddressDataPtr(value *TransactNoteAddressData) *TransactNoteAddressData {
	if value == nil {
		return nil
	}
	cloned := cloneAddressData(*value)
	return &cloned
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}

func intPtr(value int) *int {
	return &value
}

func cloneIntPtr(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneUint64Ptr(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
