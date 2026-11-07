// Minimal SSH server on golang.org/x/crypto/ssh for protocol state-machine learning.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	log.SetOutput(os.Stderr)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "tester" && string(pw) == "correct-horse-battery" {
				return nil, nil
			}
			return nil, errors.New("bad credentials")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("publickey rejected")
		},
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", ":22")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on :22")
	for {
		nc, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(nc, cfg)
	}
}

func handle(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		log.Printf("handshake error from %s: %v", nc.RemoteAddr(), err)
		return
	}
	log.Printf("handshake ok from %s user=%s client=%q", nc.RemoteAddr(), conn.User(), conn.ClientVersion())
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			log.Printf("channel accept: %v", err)
			continue
		}
		go func() {
			defer ch.Close()
			for r := range creqs {
				switch r.Type {
				case "pty-req", "shell":
					r.Reply(true, nil)
				case "exec":
					r.Reply(true, nil)
					ch.Write([]byte("hello from gossh\n"))
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				default:
					r.Reply(false, nil)
				}
			}
		}()
	}
	log.Printf("connection closed from %s", nc.RemoteAddr())
}
