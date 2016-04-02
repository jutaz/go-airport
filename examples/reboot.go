package main

import (
	"../src"
	"flag"
	"fmt"
	"net"
	"strings"
)

func main() {
	address := flag.String("address", "10.0.0.1", "Airport address.")
	password := flag.String("password", "superSecret", "Airport station password.")
	flag.Parse()
	station := &airport.Airport{
		Password: strings.TrimSpace(*password),             // Your password here.
		Address:  net.ParseIP(strings.TrimSpace(*address)), // Base station IP.
	}
	err := station.Reboot()
	if nil != err {
		panic(err)
	}
	fmt.Println("Station rebooted")
}
