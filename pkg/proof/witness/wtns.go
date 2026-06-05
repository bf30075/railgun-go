package witness

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

type WTNS struct {
	Version      uint32
	FieldByteLen uint32
	Prime        *big.Int
	Witness      []*big.Int
}

func ParseWTNS(data []byte) (WTNS, error) {
	reader := bytes.NewReader(data)
	magic := make([]byte, 4)
	if _, err := reader.Read(magic); err != nil {
		return WTNS{}, err
	}
	if string(magic) != "wtns" {
		return WTNS{}, errors.New("invalid wtns magic")
	}

	version, err := readUint32(reader)
	if err != nil {
		return WTNS{}, err
	}
	sections, err := readUint32(reader)
	if err != nil {
		return WTNS{}, err
	}
	if sections != 2 {
		return WTNS{}, fmt.Errorf("expected 2 wtns sections, got %d", sections)
	}

	sectionID, err := readUint32(reader)
	if err != nil {
		return WTNS{}, err
	}
	if sectionID != 1 {
		return WTNS{}, fmt.Errorf("expected section 1, got %d", sectionID)
	}
	sectionLength, err := readUint64(reader)
	if err != nil {
		return WTNS{}, err
	}
	fieldByteLen, err := readUint32(reader)
	if err != nil {
		return WTNS{}, err
	}
	if fieldByteLen == 0 {
		return WTNS{}, errors.New("field byte length is zero")
	}
	expectedSectionLength := uint64(8 + fieldByteLen)
	if sectionLength != expectedSectionLength {
		return WTNS{}, fmt.Errorf("section 1 length mismatch: expected %d, got %d", expectedSectionLength, sectionLength)
	}
	primeBytes := make([]byte, fieldByteLen)
	if _, err := reader.Read(primeBytes); err != nil {
		return WTNS{}, err
	}
	witnessLen, err := readUint32(reader)
	if err != nil {
		return WTNS{}, err
	}

	sectionID, err = readUint32(reader)
	if err != nil {
		return WTNS{}, err
	}
	if sectionID != 2 {
		return WTNS{}, fmt.Errorf("expected section 2, got %d", sectionID)
	}
	sectionLength, err = readUint64(reader)
	if err != nil {
		return WTNS{}, err
	}
	expectedSectionLength = uint64(fieldByteLen) * uint64(witnessLen)
	if sectionLength != expectedSectionLength {
		return WTNS{}, fmt.Errorf("section 2 length mismatch: expected %d, got %d", expectedSectionLength, sectionLength)
	}

	values := make([]*big.Int, witnessLen)
	for i := range values {
		valueBytes := make([]byte, fieldByteLen)
		if _, err := reader.Read(valueBytes); err != nil {
			return WTNS{}, err
		}
		values[i] = littleEndianToBigInt(valueBytes)
	}
	if reader.Len() != 0 {
		return WTNS{}, fmt.Errorf("unexpected trailing wtns bytes: %d", reader.Len())
	}

	return WTNS{
		Version:      version,
		FieldByteLen: fieldByteLen,
		Prime:        littleEndianToBigInt(primeBytes),
		Witness:      values,
	}, nil
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readUint32(reader *bytes.Reader) (uint32, error) {
	var out uint32
	if err := binary.Read(reader, binary.LittleEndian, &out); err != nil {
		return 0, err
	}
	return out, nil
}

func readUint64(reader *bytes.Reader) (uint64, error) {
	var out uint64
	if err := binary.Read(reader, binary.LittleEndian, &out); err != nil {
		return 0, err
	}
	return out, nil
}

func littleEndianToBigInt(value []byte) *big.Int {
	reversed := make([]byte, len(value))
	for i := range value {
		reversed[len(value)-1-i] = value[i]
	}
	return new(big.Int).SetBytes(reversed)
}
