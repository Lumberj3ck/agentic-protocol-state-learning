package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func main() {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "test" && string(password) == "test" {
				return nil, nil
			}
			return nil, errors.New("invalid credentials")
		},
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", ":22")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serve(conn, config)
	}
}

func serve(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	server, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("SSH handshake: %v", err)
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			incoming.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, requests, err := incoming.Accept()
		if err != nil {
			continue
		}
		go session(channel, requests)
	}
}

func session(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	go io.Copy(io.Discard, channel)
	for request := range requests {
		if request.Type != "exec" {
			request.Reply(false, nil)
			continue
		}
		var command struct{ Command string }
		if err := ssh.Unmarshal(request.Payload, &command); err != nil {
			request.Reply(false, nil)
			continue
		}
		request.Reply(true, nil)
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}
