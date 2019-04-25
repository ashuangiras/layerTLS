package tlslayer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
)

/*ExportKey : Export Keyfile and save it at @keyOutPath*/
func ExportKey(keyOutPath string, key interface{}) error {

	if keyOutPath == "" {
		return errors.New("Export Path Not provided")
	}
	// Converting the key
	CAKey := key.(*rsa.PrivateKey)
	keyOut, err := os.Create(keyOutPath)
	if err != nil {
		log.Println("create ca failed : ", err)
		return err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(CAKey)})
	if err != nil {
		log.Println("error in encoding cert : ", err)
		return err
	}
	log.Print("Exporting key to : ", keyOutPath)

	keyOut.Close()
	return nil
}

/*ExportCert : Export Certificate and save it at @certOutPath*/
func ExportCert(certOutPath string, certBytes []byte) error {
	if certOutPath == "" {
		return errors.New("Export Path Not provided")
	}
	certOut, err := os.Create(certOutPath)
	if err != nil {
		log.Println("create ca failed : ", err)
		return err
	}
	defer certOut.Close()
	err = pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		log.Println("error in encoding cert : ", err)
		return err
	}
	log.Print("Exporting cert to : ", certOutPath)
	return nil
}

/*ExportCSR : Export Certificate Signing Request and save it at @csrOutPath*/
func ExportCSR(csrOutPath string, certBytes []byte) error {
	// Public key
	if csrOutPath == "" {
		return errors.New("Export Path Not provided")
	}
	certOut, err := os.Create(csrOutPath)
	if err != nil {
		log.Println("create ca failed : ", err)
		return err
	}
	defer certOut.Close()
	err = pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: certBytes,
	})
	if err != nil {
		log.Println("error in encoding cert : ", err)
		return err
	}
	log.Print("Exporting csr to : ", csrOutPath)
	return nil
}
