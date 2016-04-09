package airport

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
)

// RecordType TODO
//go:generate stringer -type=RecordType
type RecordType int32

// RecordType TODO
//go:generate stringer -type=RecordEncryption
type RecordEncryption int32

const (
	// TypeCharString TODO
	TypeCharString RecordType = 0
	// TypeIPAddress TODO
	TypeIPAddress RecordType = 1
	// TypeByteString TODO
	TypeByteString RecordType = 2
	// TypePhoneNumber TODO
	TypePhoneNumber RecordType = 3
	// TypeUnsignedInteger TODO
	TypeUnsignedInteger RecordType = 4
	// TypeByte TODO
	TypeByte RecordType = 5
	// TypeLittleEndianUnsignedInteger TODO
	TypeLittleEndianUnsignedInteger RecordType = 6
)

const (
	// EncryptionUnencrypted TODO
	EncryptionUnencrypted RecordEncryption = 0
	// EncryptionEncrypted TODO
	EncryptionEncrypted RecordEncryption = 2
)

// CipherBytes TODO
var CipherBytes = []byte{
	0x0e, 0x39, 0xf8, 0x05, 0xc4, 0x01, 0x55, 0x4f, 0x0c, 0xac, 0x85, 0x7d, 0x86, 0x8a, 0xb5, 0x17,
	0x3e, 0x09, 0xc8, 0x35, 0xf4, 0x31, 0x65, 0x7f, 0x3c, 0x9c, 0xb5, 0x6d, 0x96, 0x9a, 0xa5, 0x07,
	0x2e, 0x19, 0xd8, 0x25, 0xe4, 0x21, 0x75, 0x6f, 0x2c, 0x8c, 0xa5, 0x9d, 0x66, 0x6a, 0x55, 0xf7,
	0xde, 0xe9, 0x28, 0xd5, 0x14, 0xd1, 0x85, 0x9f, 0xdc, 0x7c, 0x55, 0x8d, 0x76, 0x7a, 0x45, 0xe7,
	0xce, 0xf9, 0x38, 0xc5, 0x04, 0xc1, 0x95, 0x8f, 0xcc, 0x6c, 0x45, 0xbd, 0x46, 0x4a, 0x75, 0xd7,
	0xfe, 0xc9, 0x08, 0xf5, 0x34, 0xf1, 0xa5, 0xbf, 0xfc, 0x5c, 0x75, 0xad, 0x56, 0x5a, 0x65, 0xc7,
	0xee, 0xd9, 0x18, 0xe5, 0x24, 0xe1, 0xb5, 0xaf, 0xec, 0x4c, 0x65, 0xdd, 0x26, 0x2a, 0x15, 0xb7,
	0x9e, 0xa9, 0x68, 0x95, 0x54, 0x91, 0xc5, 0xdf, 0x9c, 0x3c, 0x15, 0xcd, 0x36, 0x3a, 0x05, 0xa7,
	0x8e, 0xb9, 0x78, 0x85, 0x44, 0x81, 0xd5, 0xcf, 0x8c, 0x2c, 0x05, 0xfd, 0x06, 0x0a, 0x35, 0x97,
	0xbe, 0x89, 0x48, 0xb5, 0x74, 0xb1, 0xe5, 0xff, 0xbc, 0x1c, 0x35, 0xed, 0x16, 0x1a, 0x25, 0x87,
	0xae, 0x99, 0x58, 0xa5, 0x64, 0xa1, 0xf5, 0xef, 0xac, 0x0c, 0x25, 0x1d, 0xe6, 0xea, 0xd5, 0x77,
	0x5e, 0x69, 0xa8, 0x55, 0x94, 0x51, 0x05, 0x1f, 0x5c, 0xfc, 0xd5, 0x0d, 0xf6, 0xfa, 0xc5, 0x67,
	0x4e, 0x79, 0xb8, 0x45, 0x84, 0x41, 0x15, 0x0f, 0x4c, 0xec, 0xc5, 0x3d, 0xc6, 0xca, 0xf5, 0x57,
	0x7e, 0x49, 0x88, 0x75, 0xb4, 0x71, 0x25, 0x3f, 0x7c, 0xdc, 0xf5, 0x2d, 0xd6, 0xda, 0xe5, 0x47,
	0x6e, 0x59, 0x98, 0x65, 0xa4, 0x61, 0x35, 0x2f, 0x6c, 0xcc, 0xe5, 0x5d, 0xa6, 0xaa, 0x95, 0x37,
	0x1e, 0x29, 0xe8, 0x15, 0xd4, 0x11, 0x45, 0x5f, 0x1c, 0xbc, 0x95, 0x4d, 0xb6, 0xba, 0x85, 0x27,
}

// InfoRecord TODO
type InfoRecord struct {
	Tag         string
	Description string
	DataType    RecordType
	Encryption  RecordEncryption
	MaxLength   int32
	Value       []byte
}

// NewInfoRecord TODO
func NewInfoRecord(tag string, description string, dataType RecordType, encryption RecordEncryption, maxLength int32, value []byte) *InfoRecord {
	airportInfoRecord := &InfoRecord{
		Tag:         tag,
		Description: description,
		DataType:    dataType,
		Encryption:  encryption,
		MaxLength:   maxLength,
	}

	if 0 == len(value) && 0 == maxLength {
		airportInfoRecord.Value = make([]byte, 0)
	} else if 0 == len(value) && 0 == maxLength {
		airportInfoRecord.Value = make([]byte, maxLength)
	} else {
		airportInfoRecord.Value = value
	}
	return airportInfoRecord
}

func (i *InfoRecord) convertToUnsignedInteger(bytes []byte) uint32 {
	return binary.BigEndian.Uint32(bytes)
}

func (i *InfoRecord) convertToIPAddress(bytes []byte) string {
	returnString := ""
	value := 0

	for j := 0; j < len(bytes)-1; j++ {
		value = int(bytes[j])
		if value < 0 {
			value += 256
		}
		returnString += strconv.Itoa(value) + "."
	}

	value = int(bytes[len(bytes)-1])
	if value < 0 {
		value += 256
	}

	returnString += strconv.Itoa(value)

	return returnString
}

// GetValue TODO
func (i *InfoRecord) GetValue() []byte {
	return i.Value
}

// SetValue TODO
func (i *InfoRecord) SetValue(bytes []byte) {
	i.Value = bytes
}

// GetUpdateBytes TODO
func (i *InfoRecord) GetUpdateBytes() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, []byte(i.Tag))
	binary.Write(buf, binary.BigEndian, i.Encryption)
	binary.Write(buf, binary.BigEndian, int32(len(i.Value)))

	if len(i.Value) > 0 {
		// encrypt bytes if needed
		if i.Encryption == EncryptionEncrypted {
			binary.Write(buf, binary.BigEndian, i.encryptBytes(CipherBytes, i.Value))
		} else {
			binary.Write(buf, binary.BigEndian, i.Value)
		}
	}

	return buf.Bytes()
}

// GetRequestBytes TODO
func (i *InfoRecord) GetRequestBytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, []byte(i.Tag))
	binary.Write(buf, binary.BigEndian, i.Encryption)
	binary.Write(buf, binary.BigEndian, int32(0))

	return buf.Bytes()
}

func (i *InfoRecord) decryptBytes(cipherString []byte, encryptedString []byte) []byte {
	return DecryptBytes(cipherString, encryptedString)
}

func (i *InfoRecord) encryptBytes(cipherString []byte, encryptedString []byte) []byte {
	return EncryptBytes(cipherString, encryptedString)
}

func (i *InfoRecord) getIntegerValue(valueBytes []byte) int32 {
	var val int32
	buf := bytes.NewReader(valueBytes)
	binary.Read(buf, binary.LittleEndian, &val)
	return val
}

func (i *InfoRecord) hexByte(b byte) string {
	// Convert single byte to byte array.
	// Output is just as encoding a single byte.
	return hex.EncodeToString([]byte{b})
}

func (i *InfoRecord) hexBytes(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

// SetBytesFromString TODO
func (i *InfoRecord) SetBytesFromString(value string) {
	var bytes []byte

	switch i.DataType {
	case TypeUnsignedInteger:
		bytes = i.convertFromUnsignedInteger(value)
		break
	case TypeLittleEndianUnsignedInteger:
		bytes = i.convertFromUnsignedInteger(value)
		bytes = i.reverseBytes(bytes)
		break
	case TypeCharString:
		fallthrough
	case TypePhoneNumber:
		if int32(len(value)) > i.MaxLength-1 {
			panic("Maximum " + string((i.MaxLength - 1)) + " characters.")
		}
		// Convert string to bytes.
		bytes = []byte(value)
		break
	case TypeIPAddress:
		bytes = i.convertFromIPv4Address(value)
		break
	case TypeByte:
		fallthrough
	case TypeByteString:
		fallthrough
	default:
		bytes = i.convertFromHexString(value)
		break
	}

	i.Value = bytes
}

func (i *InfoRecord) convertFromIPv4Address(address string) []byte {
	return net.ParseIP(address)
}

func (i *InfoRecord) convertFromUnsignedInteger(value string) []byte {
	buf := new(bytes.Buffer)
	parsed, _ := strconv.ParseUint(value, 10, 32)
	binary.Write(buf, binary.LittleEndian, parsed)
	return buf.Bytes()
}

func (i *InfoRecord) convertFromHexString(hexVal string) []byte {
	decoded, _ := hex.DecodeString(hexVal)
	return decoded
}

func (i *InfoRecord) reverseBytes(inBytes []byte) []byte {
	// From http://stackoverflow.com/a/19239850/1107285
	for i, j := 0, len(inBytes)-1; i < j; i, j = i+1, j-1 {
		inBytes[i], inBytes[j] = inBytes[j], inBytes[i]
	}

	return inBytes
}

func (i *InfoRecord) String() string {
	returnString := ""
	bytes := i.Value

	switch i.DataType {
	case TypeUnsignedInteger:
		returnString = string(i.convertToUnsignedInteger(bytes))
		break
	case TypeLittleEndianUnsignedInteger:
		bytes = i.reverseBytes(bytes)

		returnString = string(i.convertToUnsignedInteger(bytes))
		break
	case TypeCharString:
	case TypePhoneNumber:
		returnString = string(bytes[:])
		break
	case TypeIPAddress:
		returnString = i.convertToIPAddress(bytes)
		break
	case TypeByte:
	case TypeByteString:
	default:
		returnString = i.hexBytes(bytes)
		break
	}

	return returnString
}

// EncryptBytes TODO
func EncryptBytes(cipherString []byte, encryptedString []byte) []byte {
	return DecryptBytes(cipherString, encryptedString)
}

// DecryptBytes TODO
func DecryptBytes(cipherString []byte, encryptedString []byte) []byte {
	returnBytes := make([]byte, len(encryptedString))

	// just xor each byte in encryptedString with cipherString
	for i := 0; i < len(encryptedString); i++ {
		returnBytes[i] = encryptedString[i] ^ cipherString[i%256]
	}

	return returnBytes
}
