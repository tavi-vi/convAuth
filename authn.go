package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

var dataVersion uint32 = 1

type userEntryJson struct {
	Username *string
	HashAlgo *int32
	PassHash *string
}

type userEntriesJson struct {
	Version *uint32
	Users   []userEntryJson
}

type userEntry struct {
	HashAlgo int32
	PassHash string
}

type userEntries struct {
	location string
	m        sync.RWMutex
	users    atomic.Value
}

func decodeUserEntries(data []byte) (map[string]userEntry, error) {
	var badFormat = errors.New("Bad format, can't decode.")
	users := make(map[string]userEntry)

	var uj userEntriesJson
	err := json.Unmarshal(data, &uj)
	if err != nil {
		return users, err
	}

	if uj.Version == nil {
		return users, badFormat
	}
	// We only have one data version so far
	if *uj.Version != dataVersion {
		return users, errors.New("File contains wrong version number")
	}

	for _, v := range uj.Users {
		if v.Username == nil || v.HashAlgo == nil || v.PassHash == nil {
			return users, badFormat
		}
		users[*v.Username] = userEntry{*v.HashAlgo, *v.PassHash}
	}
	return users, nil
}

func (ue *userEntries) writeChanges() error {
	jdata := ue.marshal()
	return os.WriteFile(ue.location, jdata, 0600)
}

func (ue *userEntries) Update(location string) error {
	ue.m.Lock()
	defer ue.m.Unlock()

	var users map[string]userEntry
	ue.location = location

	f, err := os.Open(ue.location)
	if errors.Is(err, os.ErrNotExist) {
		ue.users.Store(users)
		return ue.writeChanges()
	} else if err != nil {
		return err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	users, err = decodeUserEntries(data)
	if err != nil {
		return err
	}

	ue.users.Store(users)
	return nil
}

func (ue *userEntries) ChangeLocation(location string) error {
	ue.m.Lock()
	defer ue.m.Unlock()

	ue.location = location
	return ue.writeChanges()
}

func (ue *userEntries) Lookup(username string) (userEntry, bool) {
	ue.m.RLock()
	defer ue.m.RUnlock()

	users := ue.users.Load().(map[string]userEntry)

	var result *userEntry
	ph, ok := users[username]
	result = &ph

	var iFromLast int
	if len(fakePassHash) > 1 {
		hash := sha256.New()
		io.WriteString(hash, username)
		hash.Write(fakePassEntropy)
		b := hash.Sum(nil)[0]
		iFromLast = int(b / 254)
	} else {
		iFromLast = 0
	}
	fh := &fakePassHash[len(fakePassHash)-1-iFromLast]

	if !ok {
		result = fh
	}
	return *result, ok
}

func (ue *userEntries) Insert(username string, entry userEntry) error {
	ue.m.Lock()
	defer ue.m.Unlock()

	users := ue.users.Load().(map[string]userEntry)
	users[username] = entry

	return ue.writeChanges()
}

// Warning: Doesn't lock ue.
func (ue *userEntries) marshal() []byte {
	users := ue.users.Load().(map[string]userEntry)

	var uej userEntriesJson
	uej.Version = &dataVersion
	for k, v := range users {
		uej.Users = append(uej.Users, userEntryJson{Username: &k, HashAlgo: &v.HashAlgo, PassHash: &v.PassHash})
	}
	jdata, err := json.Marshal(uej)
	if err != nil {
		panic(err)
	}
	return jdata
}

var fsUserEntries userEntries

func init() {

	// // We don't need this, we don't write to the file.
	// dir, err := Stat(authProxyDir)
	// if err == nil {
	//     if !dir.IsDir() {
	//         panic("config path exists and isn't a directory")
	//     }
	// } else {
	//     err = os.Mkdir(authProxyDir)
	//     if err != nil {
	//         panic(err)
	//     }
	// }

}

var loginFailure = errors.New("Invalid username or password.")

func authn(username string, password string) bool {
	entry, ok := fsUserEntries.Lookup(username)
	passCmp, err := passCompare(password, entry.PassHash, entry.HashAlgo)
	if errors.Is(err, oldAlgo) {
		println("OLD ALGO")
	}
	return ok && passCmp
}