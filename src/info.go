package airport

import (
	"bytes"
	"encoding/binary"
)

// Info TODO
type Info struct {
	records map[string]*InfoRecord
}

// NewInfo TODO
func NewInfo(retrievedBytes []byte) *Info {
	info := &Info{
		records: GetAllInfoRecords(),
	}

	if 0 == len(retrievedBytes) {
		return info
	}

	invalidBytes := []byte{0xFF, 0xFF, 0xFF, 0xF6}

	byteReader := bytes.NewReader(retrievedBytes)

	for byteReader.Len() > 0 {
		// read the tag
		tagBytes := make([]byte, 4)
		byteReader.Read(tagBytes)
		// Convert to string
		tag := string(tagBytes[:])

		if tag == "" {
			break
		}

		// get the corresponding element
		element := info.Get(tag)

		// check to make sure the element's not null, in case have received
		// unknown tag: just ignore if null
		if nil != element {
			//read the encryption
			encryptionBytes := make([]byte, 4)
			byteReader.Read(encryptionBytes)
			element.Encryption = RecordEncryption(info.GetIntegerValue(encryptionBytes))

			//read the length
			lengthBytes := make([]byte, 4)
			byteReader.Read(lengthBytes)
			length := info.GetIntegerValue(lengthBytes)

			//read the value
			valueBytes := make([]byte, length)
			byteReader.Read(valueBytes)

			if element.Encryption == EncryptionEncrypted {
				valueBytes = DecryptBytes(CipherBytes, valueBytes)
			}

			// check if the value being sent is 0xFFFFFF6; this indicates
			// the current value is invalid - just leave as 0. Ignore for
			// IP addresses, though...
			if bytes.Compare(valueBytes, invalidBytes) != 0 || element.DataType == TypeIPAddress {
				element.Value = valueBytes
			}
		} else {
			// just add an entry in hashtable
			element := &InfoRecord{}

			// assign the tag
			element.Tag = tag
			//read the encryption
			encryptionBytes := make([]byte, 4)
			byteReader.Read(encryptionBytes)
			element.Encryption = RecordEncryption(info.GetIntegerValue(encryptionBytes))
			//read the length
			lengthBytes := make([]byte, 4)
			byteReader.Read(lengthBytes)
			length := info.GetIntegerValue(lengthBytes)
			element.MaxLength = length

			//read the value
			valueBytes := make([]byte, length)
			byteReader.Read(valueBytes)

			if element.Encryption == EncryptionEncrypted {
				valueBytes = DecryptBytes(CipherBytes, valueBytes)
			}

			// check if the value being sent is 0xFFFFFF6; this indicates
			// the current value is invalid - just leave as 0. Ignore for
			// IP addresses, though...
			if bytes.Compare(valueBytes, invalidBytes) != 0 || element.DataType == TypeIPAddress {
				element.Value = valueBytes
			} else {
				element.Value = make([]byte, element.MaxLength)
			}

			// add the element
			info.Put(tag, element)
		}
	}
	return info
}

// GetUpdateBytes TODO
func (i *Info) GetUpdateBytes() []byte {
	var arr []byte
	for _, element := range i.records {
		arr = append(arr, element.GetUpdateBytes()...)
	}
	return arr
}

// GetRequestBytes TODO
func (i *Info) GetRequestBytes() []byte {
	var arr []byte
	for _, element := range i.records {
		arr = append(arr, element.GetRequestBytes()...)
	}
	return arr
}

// GetIntegerValue TODO
func (i *Info) GetIntegerValue(valueBytes []byte) int32 {
	var val int32
	buf := bytes.NewReader(valueBytes)
	binary.Read(buf, binary.BigEndian, &val)
	return val
}

// Put TODO
func (i *Info) Put(tag string, record *InfoRecord) {
	i.records[tag] = record
}

// Get TODO
func (i *Info) Get(tag string) *InfoRecord {
	record, ok := i.records[tag]
	if !ok {
		return nil
	}
	return record
}
