package tlslayer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

func GenerateCACert(isCA bool, names pkix.Name, key interface{}, expiry time.Time) (cert []byte, pemEncoded []byte, err error) {
	serial, _ := rand.Int(rand.Reader, big.NewInt(int64(65536)))
	// val, err := asn1.Marshal(basicConstraints{true, 0})
	ca := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               names,
		NotBefore:             time.Now(),
		NotAfter:              expiry,
		IsCA:                  isCA,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// Converting the key
	CAKey := key.(*rsa.PrivateKey)

	CACert, err := x509.CreateCertificate(rand.Reader, ca, ca, &CAKey.PublicKey, CAKey)
	if err != nil {
		log.Println("create ca failed", err)
		return nil, nil, err
	}

	// Encoding the certificates
	CAPemEncoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: CACert})
	return CACert, CAPemEncoded, nil
}

//GenerateCSR
func GenerateCSRFromKey(names pkix.Name, key interface{}) (csrCert []byte, csrPem []byte, serialNum *big.Int) {

	val, err := asn1.Marshal(basicConstraints{true, 0})
	if err != nil {
		log.Printf("Error in ASN marshalling: %s", err)
	}
	// step: generate a csr template
	var csrTemplate = x509.CertificateRequest{
		Subject:            names,
		SignatureAlgorithm: x509.SHA512WithRSA,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Value:    val,
				Critical: true,
			},
		},
	}
	// step: generate the csr request
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		log.Printf("Error in creating CSR cert: %s", err)
	}
	csr := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
	})
	// step: generate a serial number
	serial, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
	if err != nil {
		log.Printf("Error in generating CSR serial number: %s", err)
	}

	return csrCertificate, csr, serial
}

func GenerateRSAKeyPair(size int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, size)
	pub := &priv.PublicKey
	if err != nil {
		log.Println("Error in creating RSA Key Pair : ", err)
		return nil, nil, err
	}
	return priv, pub, nil
}

// If NO Parent present it will be self signed
func SignCertWithCA(caCert []byte, SignerPrivkey interface{}, SigneePrivKey interface{}, parentCert []byte) (cert []byte, certPem []byte, err error) {

	// Self sign if no Parent is present
	if parentCert == nil {
		parentCert = caCert
	}
	CACertBytes, err := x509.ParseCertificate(caCert)
	log.Print(err)
	CAPrivKey := SignerPrivkey.(*rsa.PrivateKey)
	SigneePubKey := &SigneePrivKey.(*rsa.PrivateKey).PublicKey
	ParentBytes, err := x509.ParseCertificate(parentCert)
	log.Print(err)

	caBytes, err := x509.CreateCertificate(rand.Reader, ParentBytes, CACertBytes, SigneePubKey, CAPrivKey)
	if err != nil {
		log.Println("create ca failed", err)
		return nil, nil, err
	}
	// Encoding the certificates
	crtBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	return caBytes, crtBytes, nil
}
