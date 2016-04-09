package airport

import (
	"bytes"
	"io"
	"net"
)

// Airport TODO
type Airport struct {
	Password string
	Address  net.IP
}

//Reboot TODO
func (a *Airport) Reboot() error {
	info := NewInfo(nil).Get("acRB").GetUpdateBytes()

	return a.write(info)
}

// GetStationName TODO
func (a *Airport) GetStationName() (string, error) {
	tag, err := a.GetProperty("syNm")

	if nil != err {
		return "", err
	}

	return string(tag.GetValue()), nil
}

// GetProperty TODO
func (a *Airport) GetProperty(tag string) (*InfoRecord, error) {
	infoRecord := NewInfo(nil).Get(tag)

	if nil == infoRecord {
		// Unknown item, lets construct it ourselves. Properties do not matter, airport will return actual ones.
		infoRecord = NewInfoRecord(tag, "", TypeByteString, EncryptionUnencrypted, 0, make([]byte, 0))
	}

	info, err := a.read(infoRecord.GetRequestBytes())

	if nil != err {
		return nil, err
	}

	return info.Get(tag), nil
}

func (a *Airport) read(requestPayload []byte) (*Info, error) {
	requestMessage := NewMessage(MessageTypeRead, a.Password, requestPayload, len(requestPayload))
	conn, err := a.createConnection()
	if nil != err {
		return nil, err
	}

	defer conn.Close()

	_, err = conn.Write(requestMessage.GetBytes())
	if nil != err {
		return nil, err
	}

	_, err = conn.Write(requestPayload)
	if nil != err {
		return nil, err
	}

	responseHeader := make([]byte, 128)

	_, err = conn.Read(responseHeader)
	if nil != err {
		return nil, err
	}

	responseBuffer := new(bytes.Buffer)
	io.Copy(responseBuffer, conn)

	return NewInfo(responseBuffer.Bytes()), nil
}

func (a *Airport) write(requestPayload []byte) error {
	requestMessage := NewMessage(MessageTypeWrite, a.Password, requestPayload, len(requestPayload))
	conn, err := a.createConnection()
	if nil != err {
		return err
	}

	defer conn.Close()

	_, err = conn.Write(requestMessage.GetBytes())
	if nil != err {
		return err
	}

	_, err = conn.Write(requestPayload)
	if nil != err {
		return err
	}

	return nil
}

func (a *Airport) createConnection() (*net.TCPConn, error) {
	address := &net.TCPAddr{
		IP:   a.Address,
		Port: 5009,
	}
	conn, err := net.DialTCP("tcp", nil, address)
	if nil != err {
		return nil, err
	}

	return conn, nil
}
