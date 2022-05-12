package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

func setPasswordOnline(username string) int {
	c, err := net.DialTimeout("unix", authProxySock, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to server: %s", err)
		return 69
	}
	entry, err := passwordPrompt()
	if err != nil {
		return 1
	}
	data, err := json.Marshal(userEntryJson{
		Username: &username,
		HashAlgo: &entry.HashAlgo,
		PassHash: &entry.PassHash,
	})
	if err != nil {
		panic(err)
	}
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:], 0)
	binary.BigEndian.PutUint32(header[4:], uint32(len(data)))
	_, err = c.Write(header)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Server appears to have hung up: %s", err)
		return 76
	}
	_, err = c.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Server appears to have hung up: %s", err)
		return 76
	}
	return 0
}

func adminInsertUser(data []byte) {
	var ue1j userEntryJson
	json.Unmarshal(data, &ue1j)
	if ue1j.Username == nil ||
		ue1j.HashAlgo == nil ||
		ue1j.PassHash == nil {

		return
	}

	ue1 := userEntry{
		HashAlgo: *ue1j.HashAlgo,
		PassHash: *ue1j.PassHash,
	}
	fsUserEntries.Insert(*ue1j.Username, ue1)
}

func serveAdminSocket(ctx context.Context) error {
	os.Remove(authProxySock)
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", authProxySock)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	dispatch := func(c net.Conn) {
		defer c.Close()
		for {
			var header [8]byte
			n, err := c.Read(header[:])
			if err != nil || n != len(header) {
				return
			}
			reqType := binary.BigEndian.Uint32(header[:4])
			length := binary.BigEndian.Uint32(header[4:])

			data := make([]byte, length)
			n, err = c.Read(data)
			if err != nil || n != int(length) {
				return
			}
			switch reqType {
			case 0:
				adminInsertUser(data)
			default:
				return
			}
		}
	}

	for {
		c, err := l.Accept()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		go dispatch(c)
	}
}
