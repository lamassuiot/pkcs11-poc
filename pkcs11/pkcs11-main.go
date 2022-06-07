package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/miekg/pkcs11"
)

func main() {
	modulePath := flag.String("module", "/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so", ".so file path")
	pin := flag.String("pin", "1234", "SoftHSM Slot 0 pin")
	flag.Parse()

	p := pkcs11.New(*modulePath)
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	fmt.Println("Total slots: ", len(slots))

	err = p.Login(session, pkcs11.CKU_USER, *pin)
	if err != nil {
		panic(err)
	}
	fmt.Println("login success")
	defer p.Logout(session)

	info, err := p.GetInfo()
	if err != nil {
		panic(err)
	}
	fmt.Println("========= PKCS 11 info ========")
	fmt.Printf("ManufacturerID: %s\n", info.ManufacturerID)
	fmt.Printf("LibraryDescription: %s\n", info.LibraryDescription)
	fmt.Printf("LibraryVersion: %x.%x\n", info.LibraryVersion.Major, info.LibraryVersion.Minor)
	fmt.Printf("CryptokiVersion: %x.%x\n", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
	fmt.Println("===============================")

	mechanismInfo, err := p.GetMechanismInfo(slots[0], []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)})
	if err != nil {
		panic(err)
	}
	fmt.Println("CKM_RSA_PKCS")
	fmt.Printf("MaxKeySize: %d\n", mechanismInfo.MaxKeySize)
	fmt.Printf("MinKeySize: %d\n", mechanismInfo.MinKeySize)
	fmt.Printf("Flags: %d\n", mechanismInfo.Flags)
	fmt.Println("===============================")

	p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})

	msgStr := "this is a string"
	msg := []byte(msgStr)
	fmt.Printf("Msg: %s\n", msgStr)

	hash, err := p.Digest(session, msg)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Hash: ")
	for _, d := range hash {
		fmt.Printf("%x", d)
	}
	fmt.Println()

	tokenLabel := "mykey"
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 16),
	}
	key, err := p.GenerateKey(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		keyTemplate)

	if err != nil {
		fmt.Printf("failed to generate keypair: %s\n", err)
		os.Exit(1)
	}

	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, make([]byte, 16))}, key); err != nil {
		fmt.Printf("EncryptInit: %s\n", err)
		os.Exit(1)
	}

	encMsg, err := p.Encrypt(session, msg)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypt: ")
	for _, d := range encMsg {
		fmt.Printf("%x", d)
	}
	fmt.Println()
	// fmt.Printf("Encrypt: %s\n", encMsg)

	if err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, make([]byte, 16))}, key); err != nil {
		fmt.Printf("DecryptInit: %s\n", err)
		os.Exit(1)
	}

	decMsg, err := p.Decrypt(session, encMsg)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypt: %s\n", string(decMsg))
}
