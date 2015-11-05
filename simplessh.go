package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"golang.org/x/crypto/ssh"
)

var port string // port to listen on

func main() {

	flag.StringVar(&port, "p", "22022", "Port to listen on.")
	flag.Parse()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// start the ssh server
	err := startServer(port)
	if err != nil {
		log.Fatal("start ssh failed. err:\n", err)
	}

	// wait for signal then shut down
	fmt.Printf("\nShutting down system on signal: %v\n", <-sigChan)
	os.Exit(0)
}

func startServer(port string) error {

	var err error

	// start the ssh server listening and return ?
	config := ssh.ServerConfig{
		PasswordCallback:  authPassword,
		PublicKeyCallback: authKey,
	}

	// generate a new private key each startcso it looks like a new server.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}

	hostPrivateKeySigner, err := ssh.ParsePrivateKey(pem.EncodeToMemory(&privateKeyBlock))
	if err != nil {
		return err
	}
	config.AddHostKey(hostPrivateKeySigner)

	socket, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}

	go listenForConn(socket, config)

	return nil
}

// listenForConn runs in a goroutine to listen for incoming connections
func listenForConn(socket net.Listener, config ssh.ServerConfig) {

	dowhile := true
	for dowhile == true {
		conn, err := socket.Accept()
		if err != nil {
			dowhile = false
		} else {
			// handle each incoming request in its own goroutine
			go handleSSH(conn, config)
		}
	}
}

// handleSSH runs in a goroutine and handles an incoming SSH connection
func handleSSH(conn net.Conn, config ssh.ServerConfig) {

	_, _, _, err := ssh.NewServerConn(conn, &config)
	if err == nil {
		log.Fatal("ssh server error: successful login. Shutting down system\n")
	}
	// goroutine ends
	conn.Close()
}

var errAuthenticationFailed = errors.New("Invalid credentials. Please try again")

// authPassword records any incoming request trying to auth with a username/password
func authPassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {

	log.Printf("sshPass: %s %s %s\n",
		conn.RemoteAddr().String(),
		conn.User(),
		strconv.QuoteToASCII(string(password)))

	return nil, errAuthenticationFailed
}

// authKey records any incoming request trying to auth with an ssh key
func authKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	h := sha256.New()
	h.Write(key.Marshal())
	sum := h.Sum(nil)

	log.Printf("sshkey: %s %s %s %s\n",
		conn.RemoteAddr().String(),
		conn.User(),
		key.Type(),
		base64.StdEncoding.EncodeToString(sum))

	return nil, errAuthenticationFailed
}

/*

 */
