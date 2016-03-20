package main

import (
	"../src"
	"fmt"
	"net"
)

func main() {
	airport := &airport.Airport{
		Password: "", // Your password here.
		Address:  net.IPv4(10, 0, 1, 1), // Base station IP.
	}
	name, err := airport.GetStationName()
	if nil != err {
		panic(err)
	}
	fmt.Printf("Station name: %s\n", name)
}
