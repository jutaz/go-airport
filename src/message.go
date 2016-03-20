package airport

import (
	"bytes"
	"encoding/binary"
	"hash/adler32"
)

const (
	// MessageTypeRead TODO
	MessageTypeRead = 0x14
	// MessageTypeWrite TODO
	MessageTypeWrite = 0x15
)

var (
	messageTag    = []byte("acpp")
	unknownField1 = []byte{0, 0, 0, 1}
	unknownField2 = make([]byte, 8)
	unknownField3 = make([]byte, 16)
	unknownField4 = make([]byte, 48)
)

// Message TODO
type Message struct {
	payloadSize     int32
	payloadChecksum uint32
	messageType     int32
	password        []byte
	messageChecksum uint32
}

// NewMessage TODO
func NewMessage(messageType int, password string, payloadBytes []byte, payloadSize int) *Message {
	airportMessage := &Message{
		password: make([]byte, 32),
	}

	if MessageTypeRead == messageType {
		airportMessage.payloadSize = int32(payloadSize)
		airportMessage.payloadChecksum = airportMessage.computeChecksum(payloadBytes)
	} else {
		airportMessage.payloadSize = int32(-1)
		airportMessage.payloadChecksum = uint32(1)
	}
	// set message type
	airportMessage.messageType = int32(messageType)

	// set encrypted password bytes
	copy(airportMessage.password, []byte(password[0:len(password)]))

	airportMessage.password = EncryptBytes(CipherBytes, airportMessage.password)
	// get current message bytes, and use to compute checksum (including magic number)
	airportMessage.messageChecksum = airportMessage.computeChecksum(airportMessage.GetBytes())
	return airportMessage
}

// GetBytes TODO
func (m *Message) GetBytes() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, messageTag)
	binary.Write(buf, binary.BigEndian, unknownField1)
	binary.Write(buf, binary.BigEndian, m.messageChecksum)
	binary.Write(buf, binary.BigEndian, m.payloadChecksum)
	binary.Write(buf, binary.BigEndian, m.payloadSize)
	binary.Write(buf, binary.BigEndian, unknownField2)
	// binary.Write(buf, binary.BigEndian, 0x00)
	binary.Write(buf, binary.BigEndian, m.messageType)
	binary.Write(buf, binary.BigEndian, unknownField3)
	binary.Write(buf, binary.BigEndian, m.password)
	binary.Write(buf, binary.BigEndian, unknownField4)

	outStream := buf.Bytes()

	if len(outStream) < 128 {
		copy(outStream, make([]byte, 128)[len(outStream)-1:])
	}

	return outStream
}

func (m *Message) computeChecksum(fileBytes []byte) uint32 {
	return adler32.Checksum(fileBytes)
}
