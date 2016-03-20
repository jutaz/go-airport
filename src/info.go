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
		records: make(map[string]*InfoRecord),
	}
	info.initializeHashtable()

	if 0 == len(retrievedBytes) {
		return info
	}

	count := 0
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
		// increment count; used at end to determine if we got any valid info
		count++

		// check to make sure the element's not null, in case have received
		// unknown tag: just ignore if null
		if nil != element {
			//read the encryption
			encryptionBytes := make([]byte, 4)
			byteReader.Read(encryptionBytes)
			element.Encryption = info.GetIntegerValue(encryptionBytes)

			//read the length
			lengthBytes := make([]byte, 4)
			byteReader.Read(lengthBytes)
			length := info.GetIntegerValue(lengthBytes)

			//read the value
			valueBytes := make([]byte, length)
			byteReader.Read(valueBytes)

			if element.Encryption == EncryptionEncryped {
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
			element.Encryption = info.GetIntegerValue(encryptionBytes)
			//read the length
			lengthBytes := make([]byte, 4)
			byteReader.Read(lengthBytes)
			length := info.GetIntegerValue(lengthBytes)
			element.MaxLength = length

			//read the value
			valueBytes := make([]byte, length)
			byteReader.Read(valueBytes)

			if element.Encryption == EncryptionEncryped {
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

func (i *Info) initializeHashtable() {
	//	Trap community password: omitted

	//	Read community password:

	i.Put("syPR", &InfoRecord{
		MaxLength:   32,
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Read community",
		Tag:         "syPR",
	})

	//	Read/write community password:

	i.Put("syPW", &InfoRecord{
		MaxLength:   32,
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Read/write community",
		Tag:         "syPW",
	})

	//	Remaining community password count: omitted

	//	Remaining community password: omitted

	//	Configuration mode switch:
	//		Modem config:     00 00 09 00
	//		Ethernet manual:  00 00 04 00
	//		Ethernet DHCP:    00 00 03 00
	//		Ethernet PPPoE:   00 00 09 00
	//

	i.Put("waCV", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeByteString,
		Encryption:  EncryptionUnencryped,
		Description: "Configuration mode",
		Tag:         "waCV",
	})

	//	Ethernet/Modem switch:
	//		00000004 = modem
	//		00000010 = Ethernet (hex)

	i.Put("waIn", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeByteString,
		Encryption:  EncryptionUnencryped,
		Description: "Ethernet/Modem switch 1",
		Tag:         "waIn",
	})

	// 	Microwave robustness flag:
	//			00 = off
	//			01 = on
	i.Put("raRo", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "Microwave robustness flag",
		Tag:         "raRo",
	})

	// 	RTS/CTS flag: not present

	// 	Closed network flag:
	//			00 = open
	//			01 = closed
	i.Put("raCl", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "Closed network flag",
		Tag:         "raCl",
	})

	//	Deny unencrypted data flag:	not present

	//	Access point density, multicast rate:
	//
	//		Multicast rate: 01 = 1 Mbps, 02 = 2 Mbps, 55 = 5.5 Mbps, 11 = 11 Mbps - all hex
	//		Density: 1 = low, 2 = medium, 3 = high
	//
	//				   large  medium   small
	//		1 Mbps		OK		OK		OK
	//		2 Mbps		OK		OK		OK
	//		5.5 Mbps	na		OK		OK
	//		11 Mbps		na		na		OK
	i.Put("raDe", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeByteString,
		Encryption:  EncryptionUnencryped,
		Description: "Access point density",
		Tag:         "raDe",
	})
	i.Put("raMu", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeByteString,
		Encryption:  EncryptionUnencryped,
		Description: "Multicast rate",
		Tag:         "raMu",
	})

	//	Select encryption key to use: not present

	//	Wireless channel:
	i.Put("raCh", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeUnsignedInteger,
		Encryption:  EncryptionUnencryped,
		Description: "Wireless channel",
		Tag:         "raCh",
	})

	//	Modem timeout, in seconds:
	i.Put("moID", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeUnsignedInteger,
		Encryption:  EncryptionUnencryped,
		Description: "Modem timeout",
		Tag:         "moID",
	})

	//	Dialing type:
	//		 	00 = tone
	//			01 = pulse
	i.Put("moPD", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "Dialing type (tone or pulse)",
		Tag:         "moPD",
	})

	//	Dialing type:
	//		00 = auto dial off
	//		01 = auto dial on
	i.Put("moAD", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "Automatic dial",
		Tag:         "moAD",
	})

	//	RTS Threshold: not present
	// 		max value 2347
	//

	//	Phone country code:
	//
	//		US standard = 	32 32 = 22 decimal
	//		Singapore = 	34 37
	//		Switzerland = 	31 35
	i.Put("moCC", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeUnsignedInteger,
		Encryption:  EncryptionUnencryped,
		Description: "Phone country code",
		Tag:         "moCC",
	})

	//	Modem country code combo box index
	i.Put("moCI", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeUnsignedInteger,
		Encryption:  EncryptionUnencryped,
		Description: "Modem country code combo box index",
		Tag:         "moCI",
	})

	//	Network name:
	i.Put("raNm", &InfoRecord{
		MaxLength:   32,
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Network name",
		Tag:         "raNm",
	})

	//
	//	Modem stuff:
	//
	i.Put("moPN", &InfoRecord{
		MaxLength:   32,
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Primary phone number",
		Tag:         "moPN",
	})
	i.Put("moAP", &InfoRecord{
		MaxLength:   32,
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Secondary phone number",
		Tag:         "moAP",
	})

	//
	//	PPPoE idle timeout, in seconds:
	//		0 = don't disconnect
	//
	i.Put("peID", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeUnsignedInteger,
		Encryption:  EncryptionUnencryped,
		Description: "PPPoE idle timeout",
		Tag:         "peID",
	})

	//	PPPoE auto connect:
	//		00 = off
	//		01 = on
	i.Put("peAC", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "PPPoE auto connect",
		Tag:         "peAC",
	})

	//	PPPoE stay connected:
	//		00 = no
	//		01 = yes
	i.Put("peSC", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "PPPoE stay connected",
		Tag:         "peSC",
	})

	// 	Encryption flag field:
	//			00 = no encryption
	//			01 = 40-bit
	//			02 = 128-bit
	i.Put("raWM", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeByteString,
		Encryption:  EncryptionUnencryped,
		Description: "Encryption switch",
		Tag:         "raWM",
	})

	//	Encryption key:
	i.Put("raWE", &InfoRecord{
		MaxLength:   13,
		DataType:    TypeByteString,
		Encryption:  EncryptionEncryped,
		Description: "Encryption key",
		Tag:         "raWE",
	})

	//	Private LAN base station address and subnet mask:
	i.Put("laIP", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeIPAddress,
		Encryption:  EncryptionEncryped,
		Description: "Private LAN base station address",
		Tag:         "laIP",
	})
	i.Put("laSM", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeIPAddress,
		Encryption:  EncryptionEncryped,
		Description: "Private LAN subnet mask",
		Tag:         "laSM",
	})

	//	syslog host facility(0 - 8): omitted
	//

	//	Bridging switch:
	//		00 = don't bridge
	//		01 = bridge
	i.Put("raWB", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "Wireless to Ethernet bridging switch",
		Tag:         "raWB",
	})

	//	Access control switch:
	//		00 = no access control
	//		01 = access control used
	i.Put("acEn", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "Access control switch",
		Tag:         "acEn",
	})

	//	Access control info:
	i.Put("acTa", &InfoRecord{
		MaxLength:   16,
		DataType:    TypeByteString,
		Encryption:  EncryptionEncryped,
		Description: "Access control info",
		Tag:         "acTa",
	})

	//	DHCP service on wireless:
	//		00 = no DHCP service
	//		01 = DHCP on, using specified range of IP addresses
	i.Put("raDS", &InfoRecord{
		MaxLength:   10,
		DataType:    TypeByte,
		Encryption:  EncryptionEncryped,
		Description: "Wireless DHCP switch",
		Tag:         "raDS",
	})

	//	DHCP service on LAN Ethernet:
	//		00 = no DHCP service
	//		01 = DHCP on
	i.Put("laDS", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "LAN Ethernet DHCP switch",
		Tag:         "laDS",
	})

	//	DHCP service on WAN Ethernet:
	//		00 = no DHCP service
	//		01 = DHCP on
	i.Put("waDS", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionEncryped,
		Description: "WAN Ethernet DHCP switch",
		Tag:         "waDS",
	})

	//	NAT switch:
	//		00 = NAT off
	//		01 = NAT on
	i.Put("raNA", &InfoRecord{
		MaxLength:   1,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "NAT switch",
		Tag:         "raNA",
	})

	//	Watchdog reboot timer switch: omit

	//	Base station IP address: 0x46A
	i.Put("waIP", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeIPAddress,
		Encryption:  EncryptionEncryped,
		Description: "Base station IP address",
		Tag:         "waIP",
	})

	//	Default TTL, for use with NAT(?): omitted

	//	Router IP address and mask: 0x470, 0x474
	i.Put("waRA", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeIPAddress,
		Encryption:  EncryptionEncryped,
		Description: "Router IP address",
		Tag:         "waRA",
	})
	i.Put("waSM", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeIPAddress,
		Encryption:  EncryptionEncryped,
		Description: "Subnet mask",
		Tag:         "waSM",
	})

	//	0x0478:  syslog IP address
	//	0x047C:  trap host IP address
	//

	//	Names of base station, contact person
	i.Put("syCt", &InfoRecord{
		MaxLength:   32,
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Contact person name",
		Tag:         "syCt",
	})
	i.Put("syNm", &InfoRecord{
		MaxLength:   32,
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Base station name",
		Tag:         "syNm",
	})

	//	Base station location:
	i.Put("syLo", &InfoRecord{
		MaxLength:   32,
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Base station location",
		Tag:         "syLo",
	})

	//	DHCP client ID:
	i.Put("waDC", &InfoRecord{
		MaxLength:   32, // guess
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "DHCP client ID",
		Tag:         "waDC",
	})

	//	DHCP address range to serve:
	//		starting address: 0xCF2
	//		ending address: 0xCF6
	i.Put("dhBg", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeIPAddress,
		Encryption:  EncryptionEncryped,
		Description: "DHCP address range start",
		Tag:         "dhBg",
	})
	i.Put("dhEn", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeIPAddress,
		Encryption:  EncryptionEncryped,
		Description: "DHCP address range end",
		Tag:         "dhEn",
	})

	//	DNS servers:
	i.Put("waD1", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeIPAddress,
		Encryption:  EncryptionEncryped,
		Description: "Primary DNS server",
		Tag:         "waD1",
	})
	i.Put("waD2", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeIPAddress,
		Encryption:  EncryptionEncryped,
		Description: "Secondary DNS server",
		Tag:         "waD2",
	})

	//	DHCP lease time:
	//		4-byte unsigned integer giving lease time in seconds
	i.Put("dhLe", &InfoRecord{
		MaxLength:   4,
		DataType:    TypeUnsignedInteger,
		Encryption:  EncryptionEncryped,
		Description: "DHCP lease time",
		Tag:         "dhLe",
	})

	//	Domain name (from DNS setting window): 0xD0A
	i.Put("waDN", &InfoRecord{
		MaxLength:   32,
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Domain name",
		Tag:         "waDN",
	})

	//	Port mapping functions:
	i.Put("pmTa", &InfoRecord{
		MaxLength:   16,
		DataType:    TypeByteString,
		Encryption:  EncryptionEncryped,
		Description: "Port mapping",
		Tag:         "pmTa",
	})

	//	Username@domain, password
	i.Put("moUN", &InfoRecord{
		MaxLength:   64, // guess
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Dial-up username",
		Tag:         "moUN",
	})
	i.Put("moPW", &InfoRecord{
		MaxLength:   64, // guess
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "Dial-up password",
		Tag:         "moPW",
	})
	i.Put("peUN", &InfoRecord{
		MaxLength:   64, // guess
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "PPPoE username",
		Tag:         "peUN",
	})
	i.Put("pePW", &InfoRecord{
		MaxLength:   64, // guess
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "PPPoE password",
		Tag:         "pePW",
	})

	//	PPPoE Service Name
	i.Put("peSN", &InfoRecord{
		MaxLength:   64, // guess!
		DataType:    TypeCharString,
		Encryption:  EncryptionEncryped,
		Description: "PPPoE service name",
		Tag:         "peSN",
	})

	//	Reboot signal
	i.Put("acRB", &InfoRecord{
		MaxLength:   0,
		DataType:    TypeByte,
		Encryption:  EncryptionUnencryped,
		Description: "Reboot flag",
		Tag:         "acRB",
	})
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
