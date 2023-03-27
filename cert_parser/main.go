package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"

	"github.com/google/go-tpm-tools/server"
)

var (
	certPEM = flag.String("certPEM", "/tmp/ekcert.pem", "ekcert")
)

func main() {
	flag.Parse()

	dat, err := os.ReadFile(*certPEM)
	if err != nil {
		log.Fatalf("could not read file cert: %s", *certPEM)
	}
	block, rest := pem.Decode(dat)
	if block == nil {
		log.Fatalf("pem.Decode not able to decode cert: %s", *certPEM)
	}
	if block.Type != "CERTIFICATE" {
		log.Fatalf("pem.Decode found unexpected PEM type: %s", block.Type)
	}
	if len(rest) > 0 {
		log.Fatalf("pem.Decode found unexpected trailing data in certificate file: %s", *certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("x509.ParseCertificate failed: %v", err)
	}

	info, err := server.GetGCEInstanceInfo(cert)
	if err != nil {
		log.Fatalf("GetGCEInstanceInfo failed: %v", err)
	}
	log.Printf("InstanceID: %v", info.InstanceId)
	log.Printf("InstanceName: %v", info.InstanceName)
	log.Printf("ProjectId: %v", info.ProjectId)
	log.Printf("ProjectNumber: %v", info.ProjectNumber)
	log.Printf("Zone: %v", info.Zone)
}
