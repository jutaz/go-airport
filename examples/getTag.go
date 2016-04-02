package main

import (
	"../src"
	"flag"
	"fmt"
	"net"
	"strings"
)

func main() {
	tag := flag.String("prop", "syNm", "Property to get from station.")
	address := flag.String("address", "10.0.0.1", "Airport address.")
	password := flag.String("password", "superSecret", "Airport station password.")

	flag.Parse()
	station := &airport.Airport{
		Password: strings.TrimSpace(*password),             // Your password here.
		Address:  net.ParseIP(strings.TrimSpace(*address)), // Base station IP.
	}
	fmt.Println(*tag)
	record, err := station.GetProperty(*tag)
	if nil != err {
		panic(err)
	}

	fmt.Printf("Got back prop: %s\n", record.Tag)

	if airport.EncryptionEncryped == record.Encryption {
		fmt.Println("Encrypted")
	} else {
		fmt.Println("Unencrypted")
	}

	switch record.DataType {
	case airport.TypeIPAddress:
		fmt.Printf("Ip address. Value: %s\n", net.ParseIP(string(record.GetValue())))
	case airport.TypeCharString:
		fmt.Printf("Value: %s\n", string(record.GetValue()))
	case airport.TypeByteString:
		fallthrough
	case airport.TypeByte:
		fallthrough
	default:
		// Print as byte string.
		fmt.Printf("Value: %v\n", record.GetValue())
	}
}
