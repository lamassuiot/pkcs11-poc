package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/ThalesIgnite/crypto11"
)

func main() {
	modulePath := flag.String("module", "/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so", ".so file path")
	pin := flag.String("pin", "1234", "SoftHSM pin")
	label := flag.String("token-label", "test", "token label")
	flag.Parse()

	config := &crypto11.Config{
		Path:       *modulePath,
		Pin:        *pin,
		TokenLabel: *label,
	}

	instance, err := crypto11.Configure(config)
	if err != nil {
		panic(err)
	}

	signer, err := instance.GenerateRSAKeyPair([]byte("hsaiz"), 2048)
	if err != nil {
		panic(err)
	}

	pub := signer.Public().(*rsa.PublicKey)

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub),
		},
	)
	fmt.Println(string(pemdata))

	signers, err := instance.FindAllKeyPairs()
	if err != nil {
		panic(err)
	}

	fmt.Println(len(signers))

	// GEN CA

	templateCA := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "ca",
			Country:            []string{"ES"},
			Province:           []string{"Gipu"},
			Locality:           []string{"Arrasate"},
			Organization:       []string{"Ikerlan"},
			OrganizationalUnit: []string{"ZPD"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &templateCA, &templateCA, pub, signer)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	fmt.Println(out.String())

	caCRT, err := x509.ParseCertificate(derBytes)
	if err != nil {
		panic(err)
	}
	// GEN Device CRT

	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)

	subj := pkix.Name{
		CommonName:         "device",
		Country:            []string{"AU"},
		Province:           []string{"Some-State"},
		Locality:           []string{"MyCity"},
		Organization:       []string{"Company Ltd"},
		OrganizationalUnit: []string{"IT"},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		panic(err)
	}

	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       caCRT.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, csr.PublicKey, signer)
	if err != nil {
		panic(err)
	}

	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
}
