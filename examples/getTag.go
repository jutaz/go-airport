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

	record, err := station.GetProperty(*tag)
	if nil != err {
		panic(err)
	}

	fmt.Println("Tag:", record.Tag)
	fmt.Println("Encryption:", record.Encryption)
	fmt.Println("Max Length:", record.MaxLength)
	fmt.Println("Type:", record.DataType)
	fmt.Println("Value:", record)
	fmt.Println("Raw value:", record.GetValue())
}
