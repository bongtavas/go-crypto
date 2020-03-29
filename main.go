package main

import(
	"fmt"
	"os"
	"errors"
	"io/ioutil"
	"github.com/romeliotavas/go-crypto/sha512"
)

func main() {
	argc := len(os.Args)
	if argc < 2 {
		err := errors.New("Please supply input file to hash")
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
        os.Exit(1)
	}

	infile := os.Args[1]

	fmt.Printf("Opening: %s \n", infile)

	indata, err := ioutil.ReadFile(infile)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	checksum := sha512.Sum512([]byte(indata))
	fmt.Printf("sha512:\t\t%x\n", checksum)
}
