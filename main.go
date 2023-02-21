package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"net"
)

const (
	listenAddress = ":7843"
)

func main() {
	ln, err := net.Listen("tcp", listenAddress)
	if err != nil {
		fmt.Println("Error listening on port 7843:", err)
		return
	}

	fmt.Println("Listening..")

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go handleConnection(conn)
	}
}

var key = []byte("AES_LOLWAT_KEYBB")

func handleConnection(conn net.Conn) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			return
		}
	}(conn)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	// Receive encrypted license key
	var encryptedMsgLen uint32
	err = binary.Read(conn, binary.LittleEndian, &encryptedMsgLen)
	if err != nil {
		fmt.Println("Problem receiving encrypted message from client:", err)
		return
	}

	encryptedMsg := make([]byte, encryptedMsgLen)
	_, err = conn.Read(encryptedMsg)
	if err != nil {
		fmt.Println("Problem receiving encrypted message from client:", err)
		return
	}

	// Decrypt license key
	nonceSize := 12
	nonce, ciphertext := encryptedMsg[:nonceSize], encryptedMsg[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil) //_ == plaintext
	if err != nil {
		fmt.Println("Problem decrypting message from client:", err)
		return
	}

	// Validate license key
	response := "VALID"

	fmt.Println("Validated key:", string(plaintext))

	/*db, err := sql.Open("mysql", "root:lol123@tcp(127.0.0.1:3306)/bbcentral")
	if err != nil {
		fmt.Println("Error connecting to MySQL database:", err)
		return
	}
	defer db.Close()

	var licenseKey string
	err = db.QueryRow("SELECT expire_at FROM license_keys WHERE key = ?", string(plaintext)).Scan(&licenseKey)
	if err != nil {
		fmt.Println("Error executing SELECT query:", err)
		return
	}

	if licenseKey == "" {
		response = "INVALID"
	} else {
		expireAt, err := strconv.Atoi(licenseKey)
		if err != nil {
			fmt.Println("Error converting expire_at value to int:", err)
			return
		}

		if expireAt < int(time.Now().Unix()) {
			response = "EXPIRED"
		}
	}*/

	// Encrypt response
	nonce = make([]byte, nonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return
	}

	ciphertext = aesgcm.Seal(nil, nonce, []byte(response), nil)

	// Send encrypted response
	encryptedResponse := append(nonce, ciphertext...)
	msgLen := uint32(len(encryptedResponse))
	err = binary.Write(conn, binary.LittleEndian, msgLen)
	if err != nil {
		fmt.Println("Problem sending encrypted response to client:", err)
		return
	}

	_, err = conn.Write(encryptedResponse)
	if err != nil {
		fmt.Println("Problem sending encrypted response to client:", err)
		return
	}
}
