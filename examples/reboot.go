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
	err := airport.Reboot()
	if nil != err {
		panic(err)
	}
	fmt.Println("Station rebooted")
}
