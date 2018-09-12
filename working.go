package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func main() {
	file, err := os.Open("customers.csv.gpg")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(reader)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fileContent := buf.Bytes()

	// The file doesn't have the csv extension, we consider it is a GPG one
	if !strings.HasSuffix("customers.csv.gpg", ".csv") {
		gpgEncrypter, err := NewGPGEncrypter1("dev-pgp.priv", "Toto1001")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		decryptedFile, err := gpgEncrypter.Decrypt(fileContent)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		reader = bufio.NewReader(bytes.NewReader(decryptedFile))
		fileContent = decryptedFile
	}

	// Ensure the file is UTF-8
	isUTF8 := utf8.Valid(fileContent)
	if !isUTF8 {
		fmt.Println(err)
		os.Exit(1)
	}

	// Consume CSV
	csvReader := csv.NewReader(reader)
	csvReader.Comma = ';'

	columns, err := csvReader.Read()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(columns)

	// [...]
}

type GPGEncrypter1 struct {
	key        *openpgp.Entity
	passphrase []byte
}

func NewGPGEncrypter1(keyLocation, passphrase string) (*GPGEncrypter1, error) {
	key, err := getKey(keyLocation)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &GPGEncrypter1{key, []byte(passphrase)}, nil
}

// getKey opens the key on disk and parse it
func getKey(keyLocation string) (*openpgp.Entity, error) {
	key, err := os.Open(keyLocation)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer key.Close()

	block, err := armor.Decode(key)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return openpgp.ReadEntity(packet.NewReader(block.Body))
}

// Decrypt decrypts the GPG encrypted data
func (b *GPGEncrypter1) Decrypt(data []byte) ([]byte, error) {
	buffer := bytes.NewBuffer(data)
	w, err := openpgp.ReadMessage(buffer, &openpgp.EntityList{b.key}, func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return b.passphrase, nil
	}, nil)
	if err != nil {
		return []byte{}, errors.New(err.Error())
	}

	decryptedData, err := ioutil.ReadAll(w.UnverifiedBody)
	if err != nil {
		return []byte{}, errors.New(err.Error())
	}

	return decryptedData, nil
}
