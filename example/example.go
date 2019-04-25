package main

import (
	"crypto/x509/pkix"
	"log"
	"time"

	"github.com/ashuangiras/tlslayer"
)

func main() {

	CAname := pkix.Name{
		CommonName:    "Localhost",
		Organization:  []string{"Localhost Ltd"},
		Country:       []string{"COUNTRY_CODE"},
		Province:      []string{"PROVINCE"},
		Locality:      []string{"CITY"},
		StreetAddress: []string{"ADDRESS"},
		PostalCode:    []string{"POSTAL_CODE"},
	}

	ServerName := pkix.Name{
		CommonName:    "localhost",
		Organization:  []string{"Localhost Server"},
		Country:       []string{"COUNTRY_CODE"},
		Province:      []string{"PROVINCE"},
		Locality:      []string{"CITY"},
		StreetAddress: []string{"ADDRESS"},
		PostalCode:    []string{"POSTAL_CODE"},
	}

	Clientname := pkix.Name{
		CommonName:    "localhost",
		Organization:  []string{"Localhost Client"},
		Country:       []string{"COUNTRY_CODE"},
		Province:      []string{"PROVINCE"},
		Locality:      []string{"CITY"},
		StreetAddress: []string{"ADDRESS"},
		PostalCode:    []string{"POSTAL_CODE"},
	}
	// Create CA key
	CAKey, _, err := tlslayer.GenerateRSAKeyPair(2048)
	exp := time.Now().AddDate(1, 0, 0)
	CACrt, CAPem, err := tlslayer.GenerateCACert(true, CAname, CAKey, exp)
	log.Print(string(CAPem))
	if err != nil {
		log.Print(err)
	}
	err = tlslayer.ExportCert("ca.crt", CACrt)
	if err != nil {
		log.Print(err)
	}
	err = tlslayer.ExportKey("ca.key", CAKey)
	if err != nil {
		log.Print(err)
	}

	// generate Server Key
	SERVERKey, _, err := tlslayer.GenerateRSAKeyPair(2048)
	SERVERCSR, CSRPem, _ := tlslayer.GenerateCSRFromKey(ServerName, SERVERKey)
	tlslayer.ExportCSR("server.csr", SERVERCSR)
	log.Print(string(CSRPem))

	tlslayer.ExportKey("server.key", SERVERKey)
	// create server certificate
	serverCERT, serverPem, _ := tlslayer.SignCertWithCA(CACrt, CAKey, SERVERKey, nil)
	tlslayer.ExportCert("server.crt", serverCERT)
	log.Print(serverPem)

	// generate Client Key
	CleintKey, _, err := tlslayer.GenerateRSAKeyPair(2048)
	CleintCSR, CSRPem, _ := tlslayer.GenerateCSRFromKey(Clientname, CleintKey)
	tlslayer.ExportCSR("client.csr", CleintCSR)
	log.Print(string(CSRPem))

	tlslayer.ExportKey("client.key", CleintKey)
	// create server certificate
	clientCERT, clientPem, _ := tlslayer.SignCertWithCA(CACrt, CAKey, CleintKey, nil)
	tlslayer.ExportCert("client.crt", clientCERT)
	log.Print(clientPem)
}
