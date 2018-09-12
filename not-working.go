package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
)

func main2() {
	var file io.ReadCloser
	file, err := os.Open("customers.csv.gpg")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()

	// The file doesn't have the csv extension, we consider it is a GPG one
	if !strings.HasSuffix("customers.csv.gpg", ".csv") {
		gpgEncrypter, err := NewGPGEncrypter2("dev-pgp.priv", "Toto1001")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		decryptedFile, err := gpgEncrypter.DecryptReader(file)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		file = ioutil.NopCloser(decryptedFile)
	}

	// Consume CSV
	csvReader := csv.NewReader(file)
	csvReader.Comma = ';'

	columns, err := csvReader.Read()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(columns)

	// [...]
}

type GPGEncrypter2 struct {
	key        *openpgp.Entity
	passphrase []byte
}

func NewGPGEncrypter2(keyLocation, passphrase string) (*GPGEncrypter2, error) {
	key, err := getKey(keyLocation)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &GPGEncrypter2{key, []byte(passphrase)}, nil
}

// DecryptReader decrypts the GPG encrypted data
func (b *GPGEncrypter2) DecryptReader(reader io.Reader) (io.Reader, error) {
	w, err := openpgp.ReadMessage(reader, &openpgp.EntityList{b.key}, func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return b.passphrase, nil
	}, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return w.UnverifiedBody, nil
}
