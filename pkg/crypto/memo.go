package railcrypto

import (
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"
)

const (
	OutputTypeTransfer       = 0
	OutputTypeBroadcasterFee = 1
	OutputTypeChange         = 2
	MemoSenderRandomNull     = "000000000000000000000000000000"
	WalletSourceMaxLength    = 16
	walletSourceCharset      = " 0123456789abcdefghijklmnopqrstuvwxyz"
)

func NormalizeWalletSource(walletSource string) (string, error) {
	normalized := strings.ToLower(walletSource)
	if err := ValidateWalletSource(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

func ValidateWalletSource(walletSource string) error {
	if len(walletSource) > WalletSourceMaxLength {
		return fmt.Errorf("wallet source must be less than %d characters", WalletSourceMaxLength)
	}
	if walletSource == "" {
		return fmt.Errorf("please add a valid wallet source")
	}
	_, err := EncodeWalletSource(walletSource)
	return err
}

func EncodeWalletSource(walletSource string) (string, error) {
	if walletSource == "" {
		return "", nil
	}
	walletSource = strings.ToLower(walletSource)
	base := big.NewInt(int64(len(walletSourceCharset)))
	output := big.NewInt(0)
	for i, char := range walletSource {
		index := strings.IndexRune(walletSourceCharset, char)
		if index < 0 {
			return "", fmt.Errorf("Invalid character for wallet source: %c", char)
		}
		positional := new(big.Int).Exp(base, big.NewInt(int64(len(walletSource)-i-1)), nil)
		output.Add(output, new(big.Int).Mul(big.NewInt(int64(index)), positional))
	}
	outputHex := output.Text(16)
	if len(outputHex)%2 == 1 {
		return outputHex, nil
	}
	return "0" + outputHex, nil
}

func DecodeWalletSource(encoded string) (string, error) {
	n, err := HexToBigInt(encoded)
	if err != nil {
		return "", err
	}
	base := big.NewInt(int64(len(walletSourceCharset)))
	zero := big.NewInt(0)
	out := ""
	for n.Cmp(zero) > 0 {
		remainder := new(big.Int).Mod(n, base)
		out = string(walletSourceCharset[remainder.Int64()]) + out
		n.Sub(n, remainder)
		n.Div(n, base)
	}
	return out, nil
}

func CreateEncryptedNoteAnnotationDataV2(outputType int, senderRandom string, walletSource string, viewingPrivateKey []byte, iv string) (string, error) {
	outputTypeHex, err := BigIntToHex(big.NewInt(int64(outputType)), 1, false)
	if err != nil {
		return "", err
	}
	senderRandomFormatted, err := FormatHexToByteLength(senderRandom, 15, false)
	if err != nil {
		return "", fmt.Errorf("sender random: %w", err)
	}
	metadataField0 := outputTypeHex + senderRandomFormatted
	if len(metadataField0) != 32 {
		return "", fmt.Errorf("metadata field 0 must be 16 bytes")
	}
	metadataField1 := strings.Repeat("0", 30)
	metadataField2, err := EncodeWalletSource(walletSource)
	if err != nil {
		return "", err
	}
	for len(metadataField2) < 30 {
		metadataField2 = "0" + metadataField2
	}
	ciphertext, err := AESCTREncryptHex(
		[]string{metadataField0, metadataField1, metadataField2},
		BytesToHex(viewingPrivateKey, false),
		iv,
	)
	if err != nil {
		return "", err
	}
	return ciphertext.IV + ciphertext.Data[0] + ciphertext.Data[1] + ciphertext.Data[2], nil
}

func CreateSenderAnnotationEncryptedV3(walletSource string, orderedOutputTypes []int, viewingPrivateKey []byte, nonce string) (string, error) {
	metadataField0, err := EncodeWalletSource(walletSource)
	if err != nil {
		return "", err
	}
	for len(metadataField0) < 32 {
		metadataField0 = "0" + metadataField0
	}
	var outputTypesFormatted strings.Builder
	for _, outputType := range orderedOutputTypes {
		outputTypeHex, err := BigIntToHex(big.NewInt(int64(outputType)), 1, false)
		if err != nil {
			return "", err
		}
		outputTypesFormatted.WriteString(outputTypeHex)
	}
	ciphertext, err := XChaCha20EncryptHex(metadataField0+outputTypesFormatted.String(), viewingPrivateKey, nonce)
	if err != nil {
		return "", err
	}
	return Prefix0x(ciphertext.Nonce + ciphertext.Bundle), nil
}

func EncodeMemoText(memoText string) string {
	if memoText == "" {
		return ""
	}
	return BytesToHex([]byte(memoText), false)
}

func DecodeMemoText(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	decoded, err := HexToBytes(encoded)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(decoded) {
		return "", fmt.Errorf("memo text is not valid UTF-8")
	}
	return string(decoded), nil
}

type NoteAnnotationData struct {
	OutputType   int
	SenderRandom string
	WalletSource string
}

type SenderAnnotationData struct {
	OutputType   int
	WalletSource string
}

func DecryptNoteAnnotationDataV2(annotationData string, viewingPrivateKey []byte) (NoteAnnotationData, error) {
	if annotationData == "" {
		return NoteAnnotationData{}, fmt.Errorf("annotation data is empty")
	}
	hexlified := Strip0x(annotationData)
	if len(hexlified) < 64 {
		return NoteAnnotationData{}, fmt.Errorf("annotation data too short")
	}
	hasTwoBytes := len(hexlified) > 64
	data := []string{hexlified[32:64]}
	if hasTwoBytes {
		end1 := minInt(len(hexlified), 96)
		end2 := minInt(len(hexlified), 128)
		data = []string{hexlified[32:64], hexlified[64:end1], hexlified[end1:end2]}
	}
	decrypted, err := AESCTRDecryptHex(
		CiphertextCTR{
			IV:   hexlified[:32],
			Data: data,
		},
		BytesToHex(viewingPrivateKey, false),
	)
	if err != nil {
		return NoteAnnotationData{}, err
	}
	if len(decrypted) == 0 || len(decrypted[0]) < 32 {
		return NoteAnnotationData{}, fmt.Errorf("invalid decrypted annotation data")
	}
	outputType, err := HexToBigInt(decrypted[0][:2])
	if err != nil {
		return NoteAnnotationData{}, err
	}
	walletSource := ""
	if len(decrypted) > 2 {
		walletSource, err = DecodeWalletSource(decrypted[2])
		if err != nil {
			return NoteAnnotationData{}, err
		}
	}
	return NoteAnnotationData{
		OutputType:   int(outputType.Int64()),
		SenderRandom: decrypted[0][2:32],
		WalletSource: walletSource,
	}, nil
}

func DecryptSenderAnnotationV3(senderCiphertext string, viewingPrivateKey []byte, transactCommitmentBatchIndex int) (SenderAnnotationData, error) {
	if senderCiphertext == "" {
		return SenderAnnotationData{}, fmt.Errorf("sender ciphertext is empty")
	}
	stripped := Strip0x(senderCiphertext)
	if len(stripped) < 32 {
		return SenderAnnotationData{}, fmt.Errorf("sender ciphertext too short")
	}
	decrypted, err := XChaCha20DecryptHex(
		CiphertextXChaCha{
			Algorithm: XChaChaEncryptionAlgorithm,
			Nonce:     stripped[:32],
			Bundle:    stripped[32:],
		},
		viewingPrivateKey,
	)
	if err != nil {
		return SenderAnnotationData{}, err
	}
	if len(decrypted) < 32 {
		return SenderAnnotationData{}, fmt.Errorf("invalid decrypted sender annotation")
	}
	walletSource, err := DecodeWalletSource(decrypted[:32])
	if err != nil {
		return SenderAnnotationData{}, err
	}
	outputTypeOffset := 32 + transactCommitmentBatchIndex*2
	if len(decrypted) < outputTypeOffset+2 {
		return SenderAnnotationData{}, fmt.Errorf("missing output type at batch index %d", transactCommitmentBatchIndex)
	}
	outputType, err := HexToBigInt(decrypted[outputTypeOffset : outputTypeOffset+2])
	if err != nil {
		return SenderAnnotationData{}, err
	}
	return SenderAnnotationData{
		OutputType:   int(outputType.Int64()),
		WalletSource: walletSource,
	}, nil
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
