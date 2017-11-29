package main

import (
	"os"
	"nettraffic/handle"
	"log"
	"os/signal"
	"syscall"
	"encoding/json"
)

func main() {

	var recData handle.SniffData

	// Listen on the interface
	sniff := handle.NewPcapSniffer()
	chanSniff := make(chan handle.SniffData)


	// On ^C or SIGTERM, gracefully stop anything running
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	f, err := os.Create("sniff.txt")
	if err != nil {
		log.Fatal("Error create file :", err)
	}
	defer f.Close()


	go func() {
		<-sigc
		log.Print("Received sigterm/sigint, stopping")
		sniff.IsRunning = false
	}()

	go func() {
		for {
			recData = <-chanSniff

			if str, err := json.Marshal(recData); err == nil {
				f.Write(str)
				f.WriteString("\n")
			} else {
				log.Fatal("Error marshaling data : ", err)
			}
		}
	}()

	if err := sniff.Open(); err != nil {
		log.Fatal("Failed to open the sniffer: ", err)
	}

	defer sniff.Close()

	log.Printf("Listening %s\n", sniff.InFace.Name)

	sniff.Listen(chanSniff)

	log.Print("Successful exit")

}
