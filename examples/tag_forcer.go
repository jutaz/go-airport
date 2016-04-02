package main

import (
	"../src"
	"bytes"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
)

var ips = []net.IP{}

var passwords = []string{}

var chars = []string{
	"a",
	"b",
	"c",
	"d",
	"e",
	"f",
	"g",
	"h",
	"i",
	"j",
	"k",
	"l",
	"m",
	"n",
	"o",
	"p",
	"q",
	"r",
	"s",
	"t",
	"u",
	"v",
	"w",
	"x",
	"y",
	"z",
	"A",
	"B",
	"C",
	"D",
	"E",
	"F",
	"G",
	"H",
	"I",
	"J",
	"K",
	"L",
	"M",
	"N",
	"O",
	"P",
	"Q",
	"R",
	"S",
	"T",
	"U",
	"V",
	"W",
	"X",
	"Y",
	"Z",
	"1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9",
	"!",
	"?",
}

func computeAllPermutationsOfCharForLength(char []string, prefix string, n int, k int, rec chan *string) {
	if k == 0 {
		rec <- &prefix
		return
	}

	for i := 0; i < n; i++ {
		computeAllPermutationsOfCharForLength(char, prefix+char[i], n, k-1, rec)
	}
}

func main() {
	ipString := flag.String("ips", "10.0.0.1", "Aiport IPs to connect to. Should be comma-separated.")
	passwordString := flag.String("passwords", "superSecret", "Corresponding AirPort passwords. Also comma-separated.")

	flag.Parse()

	splittedIps := strings.Split(*ipString, ",")
	splittedpasswords := strings.Split(*passwordString, ",")

	for _, ip := range splittedIps {
		ips = append(ips, net.ParseIP(strings.TrimSpace(ip)))
	}

	for _, password := range splittedpasswords {
		passwords = append(passwords, strings.TrimSpace(password))
	}

	var mutex = &sync.Mutex{}
	counter := 0
	latest := ""
	tmpEntriesArray := []string{}
	strChan := make(chan *string)
	workChan := make(chan []string)
	// Start entries aggregator routine.
	go func() {
		for entry := range strChan {
			mutex.Lock()
			counter++
			latest = *entry
			if 64 > len(tmpEntriesArray) {
				tmpEntriesArray = append(tmpEntriesArray, *entry)
			} else {
				workChan <- tmpEntriesArray
				tmpEntriesArray = []string{}
			}
			mutex.Unlock()
		}
	}()
	// Start tag checker routine.
	for w := 1; w <= runtime.GOMAXPROCS(0); w++ {
		go func() {
			for entry := range workChan {
				records, err := checkTags(entry)
				if nil != err {
					time.Sleep(50 * time.Millisecond)
					workChan <- entry
					return
				}
				for _, record := range records {
					if nil != record {
						fmt.Printf("Got new entry: %s - %+v\n", record.Tag, record.GetValue())
					}
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	// Start clock.
	ticker := time.NewTicker(5 * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				fmt.Printf("Processed: %d. Current Tag: %s\n", counter, latest)
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
	// Start computing all possible tags.
	computeAllPermutationsOfCharForLength(chars, "", len(chars), 4, strChan)
	close(quit)
	close(strChan)
}

func read(requestPayload []byte) ([]byte, error) {
	station := rand.Intn(len(ips))
	requestMessage := airport.NewMessage(airport.MessageTypeRead, passwords[station], requestPayload, len(requestPayload))
	conn, err := createConnection(ips[station])
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

	return responseBuffer.Bytes(), nil
}

func createConnection(ip net.IP) (*net.TCPConn, error) {
	address := &net.TCPAddr{
		IP:   ip,
		Port: 5009,
	}
	conn, err := net.DialTCP("tcp", nil, address)
	if nil != err {
		return nil, err
	}

	return conn, nil
}

func checkTags(expectedTags []string) ([]*airport.InfoRecord, error) {
	var payload []byte
	var foundTags []*airport.InfoRecord

	for _, expectedTag := range expectedTags {
		payload = append(payload, airport.NewInfoRecord(expectedTag, "", airport.TypeByteString, airport.EncryptionUnencrypted, 0, make([]byte, 0)).GetRequestBytes()...)
	}
	data, err := read(payload)
	if nil != err {
		return []*airport.InfoRecord{}, err
	}
	info := airport.NewInfo(data)

	for _, expectedTag := range expectedTags {
		element := info.Get(expectedTag)
		if nil != element && (4 != element.MaxLength || 0 != bytes.Compare(element.GetValue(), make([]byte, element.MaxLength))) {
			foundTags = append(foundTags, element)
		}
	}

	return foundTags, nil
}
