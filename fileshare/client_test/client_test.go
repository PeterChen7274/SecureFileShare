package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	"fmt"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

func contains(slice []userlib.UUID, key uuid.UUID) bool {
	for _, item := range slice {
		if item == key {
			return true
		}
	}
	return false
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

func genUUID(a, b []byte) uuid.UUID {
	argon2Key := userlib.Argon2Key(a, b, 16)
	res, err := uuid.FromBytes(argon2Key)

	if err != nil {
		return uuid.Nil
	}
	return res
}

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing store file cause overriding.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Store file data: %s", contentThree)
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
		})

		Specify("Basic Test: Testing being able to detect wrong password and file tampering", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop).")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Try to use wrong password")
			aliceLaptop, err = client.GetUser("alice", defaultPassword+"wrong")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Create user that is case sensitive")
			aliceLaptop, err = client.InitUser("Alice", defaultPassword+"wrong")
			Expect(err).To(BeNil())
			aliceLaptop, err = client.InitUser("aliCe", defaultPassword+"wrong")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Ruin Alice's data, pls detect this")
			// user_uuid := genUUID([]byte(defaultPassword), []byte("idalice"))
			// userlib.DatastoreSet(user_uuid, userlib.RandomBytes(16))
			uuids := userlib.DatastoreGetMap()
			for key := range uuids {
				userlib.DatastoreSet(key, userlib.RandomBytes(10))
			}
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			// userlib.DebugMsg("Only change bob's cipher text, pls detect this")
			// user_uuid = genUUID([]byte(defaultPassword), []byte("idbob"))
			// x, _ := userlib.DatastoreGet(user_uuid)
			// var ch CipherAndHMAC
			// var chp = &ch
			// json.Unmarshal(x, chp)
			// chp.CipherText = userlib.RandomBytes(32)
			// ch = *chp
			// y, _ := json.Marshal(ch)
			// userlib.DatastoreSet(user_uuid, y)
			_, errr := client.GetUser("bob", defaultPassword)
			Expect(errr).ToNot(BeNil())
		})

		Specify("Basic Test: Testing empty username and creating same users", func() {
			userlib.DebugMsg("Initializing users with empty name.")
			aliceDesktop, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Get a non existent user.")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing users Alice (aliceDesktop).")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Trying to create alice again")
			aliceLaptop, err = client.InitUser("alice", defaultPassword+"wrong")
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: Testing integrity of invitations", func() {
			userlib.DebugMsg("Initializing a user.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing another user.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Store file data: %s", contentThree)
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Invite bob")
			inv, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreSet(inv, userlib.RandomBytes(10))

			userlib.DebugMsg("Tampered invitations should be detected")
			err = bob.AcceptInvitation("alice", inv, bobFile)
			Expect(err).ToNot(BeNil())
		})

		// Specify("Test: putting file append to stress", func() {
		// 	userlib.DebugMsg("Initializing users alice.")
		// 	alice, err = client.InitUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Create a file.")
		// 	c := contentOne
		// 	for i := 0; i < 99; i++ {
		// 		c += contentOne
		// 	}
		// 	err = alice.StoreFile(aliceFile, []byte(c))
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
		// 	data, err := alice.LoadFile(aliceFile)
		// 	Expect(err).To(BeNil())
		// 	Expect(data).To(Equal([]byte(c)))

		// 	userlib.DebugMsg("Append many times.")
		// 	d := c
		// 	for i := 0; i < 99; i++ {
		// 		if i%10 == 0 {
		// 			fmt.Println("Progresssssss")
		// 		}
		// 		d += c
		// 		err = alice.AppendToFile(aliceFile, []byte(c))
		// 		Expect(err).To(BeNil())
		// 	}

		// 	userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
		// 	data, err = alice.LoadFile(aliceFile)
		// 	Expect(err).To(BeNil())
		// 	Expect(data).To(Equal([]byte(d)))
		// })

		Specify("Basic Test: deleting datastore cause file ops to fail", func() {
			userlib.DebugMsg("Initializing users alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create a file.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Append to the file.")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			uuids := userlib.DatastoreGetMap()
			for key := range uuids {
				userlib.DatastoreDelete(key)
			}
			userlib.DebugMsg("You shouldn't be able to append to or load a file")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: different users, same filename", func() {
			userlib.DebugMsg("Initializing users.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create a file.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Append then load a file")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: deleting specific datastore values cause file ops to fail", func() {
			userlib.DebugMsg("Initializing users alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create a file.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			uuids := userlib.DatastoreGetMap()

			var keysList []uuid.UUID
			for key := range uuids {
				keysList = append(keysList, key)
			}

			userlib.DebugMsg("Append to the file.")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			uuids2 := userlib.DatastoreGetMap()

			// fmt.Println("LEEEEENNNNNNN")
			// fmt.Println(len(keysList))
			// fmt.Println(len(uuids2))
			for key := range uuids2 {
				if !contains(keysList, key) {
					// fmt.Println("EXECUTED")
					userlib.DatastoreSet(key, userlib.RandomBytes(55))
				}
			}
			userlib.DebugMsg("You should be able to append to but not load a file")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: tampering files cause file ops to fail", func() {
			userlib.DebugMsg("Initializing users alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create a file.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Append to the file.")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			uuids := userlib.DatastoreGetMap()
			for key := range uuids {
				userlib.DatastoreSet(key, userlib.RandomBytes(10))
			}
			// content_key := userlib.Argon2Key(file.ContentKey, file.StarterByte, 16)
			// content_hmac := userlib.Argon2Key(content_key, file.StarterByte, 16)
			// content, err := client.GetContent(file.Start, content_key, content_hmac)
			// Expect(err).To(BeNil())
			// Expect(content.Plaintext).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("You shouldn't be able to load a file")

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			// userlib.DatastoreSet(file_uuid, old_file)

			// userlib.DebugMsg("Should be back to normal")
			// err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			// Expect(err).To(BeNil())

			// userlib.DebugMsg("So it's append's fault?")
			// data, err = alice.LoadFile(aliceFile)
			// Expect(err).To(BeNil())
			// Expect(data).To(Equal([]byte(contentOne + contentTwo + contentTwo)))

			// userlib.DatastoreSet(file.Start, userlib.RandomBytes(10))
			// // userlib.DebugMsg("You shouldn't be able to append to or load a file")
			// // err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			// // Expect(err).ToNot(BeNil())

			// data, err = alice.LoadFile(aliceFile)
			// Expect(err).ToNot(BeNil())
			// Expect(data).ToNot(Equal([]byte(contentOne + contentTwo + contentTwo)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			_, err = aliceLaptop.CreateInvitation(aliceFile+"sfef", "bob")
			Expect(err).ToNot(BeNil())
			_, err = aliceLaptop.CreateInvitation(aliceFile, "chad")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = alice.RevokeAccess(aliceFile+"ejife", "bob")
			Expect(err).ToNot(BeNil())
			err = alice.RevokeAccess(aliceFile, "chad")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("More Test: Invitation and revokation with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = aliceDesktop.StoreFile(aliceFile+"2", []byte(contentOne))
			Expect(err).To(BeNil())
			err = aliceDesktop.StoreFile(aliceFile+"3", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			invite2, err := aliceLaptop.CreateInvitation(aliceFile+"2", "bob")
			Expect(err).To(BeNil())

			invite3, err := aliceLaptop.CreateInvitation(aliceFile+"3", "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop revoke invite for Bob before he receives it.")
			err = aliceLaptop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob storing file %s with content: %s", bobFile+"4", contentOne)
			err = bob.StoreFile(bobFile+"4", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop revoke invite again for Bob, this is an error.")
			err = aliceLaptop.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice, but he's already revoked.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
			err = bob.AcceptInvitation("alice", invite2, bobFile+"4")
			Expect(err).ToNot(BeNil())
			err = bob.AcceptInvitation("alice", invite2, bobFile+"2")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("alice", invite3, eveFile+"3")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file when he doesn't have access")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
			err = bob.AppendToFile(bobFile+"2", []byte(contentThree))
			Expect(err).To(BeNil())
			err = eve.AppendToFile(eveFile+"3", []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop recreate invitation for Bob.")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
			data, err = aliceDesktop.LoadFile(aliceFile + "3")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))
			data, err = eve.LoadFile(eveFile + "3")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))
			_, err = eve.LoadFile(aliceFile + "3")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob store (overwrite) the file")
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Charles store (overwrite) the file")
			err = charles.StoreFile(charlesFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Doris accepting invite under name %s.", aliceFile, dorisFile)
			invite, err = aliceDesktop.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris accepting invite from Alice.")
			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Doris can load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Eve tries to accept invite from Alice, which doesn't exist.")
			err = eve.AcceptInvitation("alice", invite, eveFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = aliceDesktop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = aliceDesktop.RevokeAccess(aliceFile+"3", "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = aliceDesktop.LoadFile(aliceFile + "3")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))

			userlib.DebugMsg("Checking that Doris can still load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Doris and Alice can still append and load the file.")
			err = doris.AppendToFile(dorisFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Bob tries to re accept invite from Alice after being revoked.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
			err = eve.AcceptInvitation("alice", invite3, eveFile+"3")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Eve for file %s, and Eve accepting invite under name %s.", aliceFile, eveFile)
			invite, err = aliceDesktop.CreateInvitation(aliceFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve accepts invite from Alice.")
			err = eve.AcceptInvitation("alice", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Eve can append and load the file.")
			err = eve.AppendToFile(eveFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentTwo)))

			userlib.DebugMsg("Doris revoking Alice's access from %s. Make sure this is not possible", dorisFile)
			err = doris.RevokeAccess(dorisFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking Doris's access from %s.", aliceFile)
			err = aliceDesktop.RevokeAccess(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Eve and Alice can still store and load the file.")
			err = eve.StoreFile(eveFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))

			userlib.DebugMsg("Bob tries to re accept invite from Alice after being revoked.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = doris.AppendToFile(dorisFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob/Charles/Doris lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())

			bob2, _ := client.GetUser("bob", defaultPassword)

			data, err = bob2.LoadFile(bobFile + "2")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))

			_, err = bob2.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = bob.LoadFile(bobFile + "2")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))

			_, err = eve.LoadFile(eveFile + "3")
			Expect(err).ToNot(BeNil())

			data, err = aliceDesktop.LoadFile(aliceFile + "2")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))
		})

		Specify("More Test: bunch of invitations", func() {
			others := [4]string{"bob", "charles", "doris", "eve"}
			var invitations [4]uuid.UUID
			userlib.DebugMsg("Initializing users.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create files.")
			for i := 0; i < 5; i++ {
				err = alice.StoreFile(aliceFile+fmt.Sprintf("%d", i), []byte(contentOne))
				Expect(err).To(BeNil())
			}
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create invitations.")

			for i := range others {
				inv, err := alice.CreateInvitation(aliceFile+"0", others[i])
				Expect(err).To(BeNil())
				invitations[i] = inv
			}
			inv2, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			inv3, err := alice.CreateInvitation(aliceFile+"1", "bob")
			Expect(err).To(BeNil())
			inv4, err := alice.CreateInvitation(aliceFile+"2", "charles")
			Expect(err).To(BeNil())
			inv5, err := alice.CreateInvitation(aliceFile+"3", "doris")
			Expect(err).To(BeNil())
			inv6, err := alice.CreateInvitation(aliceFile+"4", "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Accept invitations.")
			err = bob.AcceptInvitation("alice", invitations[0], bobFile+"1")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", inv3, bobFile+"2")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invitations[1], charlesFile)
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("bob", inv2, charlesFile+"1")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("alice", invitations[2], dorisFile)
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("alice", invitations[3], eveFile)
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", inv4, charlesFile+"2")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("alice", inv5, dorisFile+"1")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("alice", inv6, eveFile+"1")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that everyone sees expected file data.")
			data, err := alice.LoadFile(aliceFile + "0")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = bob.LoadFile(bobFile + "1")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = charles.LoadFile(charlesFile + "1")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = doris.LoadFile(dorisFile + "1")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Revoke.")
			err = alice.RevokeAccess(aliceFile+"0", "bob")
			Expect(err).To(BeNil())
			err = alice.RevokeAccess(aliceFile+"2", "charles")
			Expect(err).To(BeNil())
			err = alice.RevokeAccess(aliceFile+"0", "doris")
			Expect(err).To(BeNil())
			err = alice.RevokeAccess(aliceFile+"0", "charles")
			Expect(err).To(BeNil())
			err = bob.RevokeAccess(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check if everyone has correct access.")
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			userlib.DebugMsg("Check if eve has correct access.")
			data, err = eve.LoadFile(eveFile + "1")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			userlib.DebugMsg("Check if doris has correct access.")
			data, err = doris.LoadFile(dorisFile + "1")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			userlib.DebugMsg("Check if doris has correct access.")
			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Check if bob has correct access.")
			_, err = bob.LoadFile(bobFile + "1")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Check if charles has correct access.")
			_, err = charles.LoadFile(charlesFile + "1")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Check if charles has correct access.")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Check if doris has correct access.")
			err = doris.StoreFile(dorisFile+"1", []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = doris.LoadFile(dorisFile + "1")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			userlib.DebugMsg("Check if alice has correct access.")
			data, err = alice.LoadFile(aliceFile + "3")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			userlib.DebugMsg("Check if alice has correct access.")
			data, err = alice.LoadFile(aliceFile + "2")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			uuids := userlib.DatastoreGetMap()
			for key := range uuids {
				userlib.DatastoreSet(key, userlib.RandomBytes(10))
			}
			_, err = alice.LoadFile(aliceFile + "2")
			Expect(err).ToNot(BeNil())
		})
	})
})
