package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
	Password      []byte
	loggedIn      bool              // Whether the user is currently logged in
	RSAKey        userlib.PKEDecKey // RSA key of the user (private decryption key)
	SignKey       userlib.DSSignKey // Signing key (private key for digital signatures)
	FileKey       []byte            // File key used for file encryption/decryption
	ConversionKey []byte            // Conversion key (used for invitation)
	Shared_Users  uuid.UUID
	Revoked_times uuid.UUID
}

type File struct {
	Fake           bool      // Whether the file is a fake object
	Start          uuid.UUID // Start UUID of the file object
	End            uuid.UUID // End UUID of the file object
	FileKey        []byte    // File key used for file encryption/decryption
	HMACKey        []byte    // Key used for computing HMAC on the file content
	ContentKey     []byte
	ContentHmac    []byte
	ConversionKey  []byte // Key used for invitation on the file
	ConversionHmac []byte
	StarterByte    []byte
	Content_num    int
}

type Content struct {
	Plaintext []byte    // Plaintext of the content
	Child     uuid.UUID // Child UUID for linking to next content
}

type CipherAndHMAC struct {
	CipherText []byte
	HMAC       []byte
	Password   []byte
	Signature  []byte
}

type Invitation struct {
	Conversion_UUID uuid.UUID
	File_key        []byte
	HMAC            []byte
	Conversion_key  []byte
	Conversion_hmac []byte
}

type Conversion struct {
	File_UUID uuid.UUID
}

// Generate UUID from two byte arrays
func genUUID(a, b []byte) uuid.UUID {
	argon2Key := userlib.Argon2Key(a, b, 16)
	res, err := uuid.FromBytes(argon2Key)

	if err != nil {
		return uuid.Nil
	}
	return res
}

// Generate ciphertext and hmac from plaintext and 2 keys
func EncryptThenMAC(p, ek, mk []byte) ([]byte, []byte) {
	// Encrypt the plaintext p using the encryption key ek
	encryptedData := userlib.SymEnc(ek, userlib.RandomBytes(16), p)

	// Compute HMAC on the encrypted data using the MAC key mk
	hmac, err := userlib.HMACEval(mk, encryptedData)

	if err != nil {
		return nil, nil
	}

	// Concatenate the encrypted data and the HMAC to create the final ciphertext
	return encryptedData, hmac
}

// Given whole encryption object, verify hmac and return actual ciphertext
func CheckHMAC(obj *CipherAndHMAC, mk []byte) ([]byte, bool) {
	encryption := obj.CipherText
	hmac := obj.HMAC
	computed_hmac, err := userlib.HMACEval(mk, encryption)
	if err != nil {
		return nil, false
	}
	if !userlib.HMACEqual(hmac, computed_hmac) {
		return nil, false
	}
	return encryption, true
}

// Get content given uuid, and 2 keys
func GetContent(u uuid.UUID, ek []byte, mk []byte) (*Content, error) {
	var c Content
	var cp = &c
	var ch CipherAndHMAC
	var chp = &ch
	encrypted_content, ok := userlib.DatastoreGet(u)
	if !ok {
		return nil, errors.New("content doesn't exist")
	}
	json.Unmarshal(encrypted_content, chp)
	encryption, success := CheckHMAC(chp, mk)
	if !success {
		return nil, errors.New("content has issue")
	}
	content_array := userlib.SymDec(ek, encryption)
	json.Unmarshal(content_array, cp)
	return cp, nil
}

// Get a file when given the conversion id, and two keys
func GetFileFromConversion(u uuid.UUID, ek []byte, mk []byte, fek []byte, fmk []byte) (*File, error) {
	var ch CipherAndHMAC
	var chp = &ch
	var c Conversion
	var cp = &c
	encrypted_file, ok := userlib.DatastoreGet(u)
	if !ok {
		return nil, errors.New("access revoked, give it up")
	}
	json.Unmarshal(encrypted_file, chp)
	encryption, success := CheckHMAC(chp, mk)
	if !success {
		return nil, errors.New("file has issue")
	}
	conversion_byte := userlib.SymDec(ek, encryption)
	json.Unmarshal(conversion_byte, cp)
	return GetFile(cp.File_UUID, fek, fmk)
}

// Get a file, period
func GetFile(u uuid.UUID, ek []byte, mk []byte) (*File, error) {
	var ch CipherAndHMAC
	var chp = &ch
	var file File
	var fileptr = &file
	datastoreValue, found := userlib.DatastoreGet(u)
	if !found {
		return nil, errors.New("file not found")
	}
	json.Unmarshal(datastoreValue, chp)
	encryptedData, success := CheckHMAC(chp, mk)
	if !success {
		return nil, errors.New("file corrupted")
	}
	file_byte := userlib.SymDec(ek, encryptedData)
	json.Unmarshal(file_byte, fileptr)
	if fileptr.Fake {
		file_key := fileptr.FileKey
		file_hmac := fileptr.HMACKey
		fileptr, err := GetFileFromConversion(fileptr.Start, fileptr.ConversionKey, fileptr.ConversionHmac, file_key, file_hmac)
		if err != nil {
			return nil, err
		}
		return fileptr, nil
	}
	return fileptr, nil
}

func FakeFile(u uuid.UUID, ek []byte, mk []byte) (*File, bool, error) {
	var ch CipherAndHMAC
	var chp = &ch
	var file File
	var fileptr = &file
	datastoreValue, found := userlib.DatastoreGet(u)
	if !found {
		return nil, false, errors.New("file not found")
	}
	json.Unmarshal(datastoreValue, chp)
	encryptedData, success := CheckHMAC(chp, mk)
	if !success {
		return nil, false, errors.New("file corrupted")
	}
	file_byte := userlib.SymDec(ek, encryptedData)
	json.Unmarshal(file_byte, fileptr)
	return fileptr, fileptr.Fake, nil
}

func FileParent(u uuid.UUID, ek []byte, mk []byte) (uuid.UUID, error) {
	var ch CipherAndHMAC
	var chp = &ch
	var c Conversion
	var cp = &c
	encrypted_file, ok := userlib.DatastoreGet(u)
	if !ok {
		return uuid.Nil, errors.New("access revoked, give it up")
	}
	json.Unmarshal(encrypted_file, chp)
	encryption, success := CheckHMAC(chp, mk)
	if !success {
		return uuid.Nil, errors.New("file has issue")
	}
	conversion_byte := userlib.SymDec(ek, encryption)
	json.Unmarshal(conversion_byte, cp)
	return cp.File_UUID, nil
}

// Push an object into the data store
func EasySet(obj interface{}, u uuid.UUID, ek []byte, mk []byte) error {
	var ch CipherAndHMAC
	var chp = &ch
	conversion_m, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	conversion_encr, conversion_hmac := EncryptThenMAC(conversion_m, ek, mk)
	chp.CipherText = conversion_encr
	chp.HMAC = conversion_hmac
	final_conversion, err := json.Marshal(ch)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(u, final_conversion)
	return nil
}

func HybridEncryption(ek userlib.PKEEncKey, p []byte) ([]byte, []byte, error) {
	key := userlib.RandomBytes(16)
	k, err := userlib.PKEEnc(ek, key)
	if err != nil {
		return nil, nil, err
	}
	c := userlib.SymEnc(key, userlib.RandomBytes(16), p)
	return c, k, nil
}

func FindLstByUUID(user *User, u uuid.UUID) (map[string][]string, error) {
	var ch CipherAndHMAC
	var chp = &ch
	var lst map[string][]string
	var lstptr = &lst
	x, ok := userlib.DatastoreGet(u)
	if !ok {
		return nil, errors.New("list not found")
	}
	lst_key := userlib.Argon2Key(user.Password, []byte("lst"+user.Username), 16)
	lst_hmac := userlib.Argon2Key(lst_key, []byte("lst"+string(user.Password)), 16)
	err := json.Unmarshal(x, chp)
	if err != nil {
		return nil, err
	}
	enc, ok := CheckHMAC(chp, lst_hmac)
	if !ok {
		return nil, errors.New("list corrupted")
	}
	decr := userlib.SymDec(lst_key, enc)
	err = json.Unmarshal(decr, lstptr)
	if err != nil {
		return nil, err
	}
	lst = *lstptr
	return lst, nil
}

func FindNumByUUID(user *User, u uuid.UUID) (map[string]int, error) {
	var ch CipherAndHMAC
	var chp = &ch
	var num map[string]int
	var numptr = &num
	x, ok := userlib.DatastoreGet(u)
	if !ok {
		return nil, errors.New("num not found")
	}
	lst_key := userlib.Argon2Key(user.Password, []byte("num"+user.Username), 16)
	lst_hmac := userlib.Argon2Key(lst_key, []byte("num"+string(user.Password)), 16)
	err := json.Unmarshal(x, chp)
	if err != nil {
		return nil, err
	}
	enc, ok := CheckHMAC(chp, lst_hmac)
	if !ok {
		return nil, errors.New("num corrupted")
	}
	decr := userlib.SymDec(lst_key, enc)
	err = json.Unmarshal(decr, numptr)
	if err != nil {
		return nil, err
	}
	num = *numptr
	return num, nil
}

func AddOneToByteArray(arr []byte) []byte {
	result := make([]byte, len(arr))
	copy(result, arr)

	carry := true
	for i := len(result) - 1; i >= 0 && carry; i-- {
		if result[i] < 255 {
			result[i]++
			carry = false
		} else {
			result[i] = 0
		}
	}
	if carry {
		result = append([]byte{1}, result...)
	}
	return result
}

func ComplexFileUUID(user *User, filename string) (uuid.UUID, error) {
	arr, err := FindNumByUUID(user, user.Revoked_times)

	if err != nil {
		return uuid.Nil, err
	}

	x := 0
	y, found := arr[filename]

	// fmt.Println("Pushed?")
	// fmt.Println(y)
	// fmt.Print(found)

	if found {
		x = y
	}
	file_uuid := genUUID([]byte(user.Username), []byte(filename))
	for i := 0; i < x; i++ {
		file_uuid, _ = uuid.FromBytes(userlib.Argon2Key(user.Password, file_uuid[:], 16))
	}
	return file_uuid, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// fmt.Println("test")
	// fmt.Println(userlib.Argon2Key([]byte("peter"), []byte("chen"), 16))
	// fmt.Println(userlib.Argon2Key([]byte("pete"), []byte("rchen"), 16))
	var user User
	userdataptr = &user
	var ch CipherAndHMAC
	var chp = &ch
	// Check if the username is empty
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}

	userdataptr.Username = username

	// Check if the username already exists in the keystore
	_, exists := userlib.KeystoreGet(username)
	if exists {
		return nil, errors.New("username already exists")
	}

	// Generate a signing key pair
	signPrivateKey, signPublicKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// Generate an RSA key pair
	rsaPublicKey, rsaPrivateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	// Store the verification key of the signing key in keystore
	userlib.KeystoreSet(username, signPublicKey)

	// Store the public RSA key in keystore
	rsaKeyHash := userlib.Hash([]byte(username))
	rsaKeyString := string(rsaKeyHash[:])
	userlib.KeystoreSet(rsaKeyString, rsaPublicKey)

	// Assign user's RSAKey and SignKey
	userdataptr.RSAKey = rsaPrivateKey
	userdataptr.SignKey = signPrivateKey

	// Generate two 16-byte keys randomly
	userdataptr.FileKey = userlib.RandomBytes(16)
	userdataptr.ConversionKey = userlib.RandomBytes(16)
	userdataptr.loggedIn = true
	userdataptr.Password = []byte(password)

	Shared_Users := make(map[string][]string)
	Revoked_times := make(map[string]int)

	userdataptr.Shared_Users = uuid.New()
	userdataptr.Revoked_times = uuid.New()

	// if userdataptr.Shared_Users == userdataptr.Revoked_times {
	// 	fmt.Println("WHAAT THE FUCCCKKKK")
	// }

	lst_key := userlib.Argon2Key([]byte(password), []byte("lst"+username), 16)
	lst_hmac := userlib.Argon2Key(lst_key, []byte("lst"+password), 16)

	num_key := userlib.Argon2Key([]byte(password), []byte("num"+username), 16)
	num_hmac := userlib.Argon2Key(num_key, []byte("num"+password), 16)

	EasySet(Shared_Users, user.Shared_Users, lst_key, lst_hmac)
	EasySet(Revoked_times, user.Revoked_times, num_key, num_hmac)

	// Generate a 16-byte Argon2 key with password and username as salt
	argon2Key := userlib.Argon2Key([]byte(password), []byte(username), 16)
	argon2Hmac := userlib.Argon2Key([]byte(password), []byte("hmac"+username), 16)

	// Marshal the user struct
	userData, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	// hmac the password
	hmac_p, err := userlib.HMACEval(argon2Hmac, []byte(password))
	if err != nil {
		return nil, err
	}

	// Generate another 16-byte Argon2 key with password and "+"+username as salt, use it to create a deterministic UUID
	argon2KeyUUID := genUUID([]byte(password), []byte("id"+username))

	// Encrypt then hmac the user data || 64-byte hmac of password and store in datastore
	en, mac := EncryptThenMAC(userData, argon2Key, argon2Hmac)
	chp.CipherText = en
	chp.HMAC = mac
	chp.Password = hmac_p
	datastoreValue, err := json.Marshal(ch)

	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(argon2KeyUUID, datastoreValue)

	// Return the pointer to the created user
	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	var ch CipherAndHMAC
	var chp = &ch
	_, exists := userlib.KeystoreGet(username)
	if !exists {
		return nil, errors.New("user not found")
	}

	// Generate an UUID from argon2 key (password, "+"+username)
	argon2KeyUUID := genUUID([]byte(password), []byte("id"+username))

	// Retrieve user from datastore using the generated UUID
	datastoreValue, ok := userlib.DatastoreGet(argon2KeyUUID)
	if !ok {
		return nil, errors.New("user not found")
	}

	json.Unmarshal(datastoreValue, chp)

	// Compute an argon2 key (password, "hmac"+username)
	argon2KeyForHMAC := userlib.Argon2Key([]byte(password), []byte("hmac"+username), 16)

	// Compute pass word HMAC using the key and the password
	passwordHMAC, err := userlib.HMACEval(argon2KeyForHMAC, []byte(password))

	if err != nil {
		return nil, err
	}

	// Verify password
	if !userlib.HMACEqual(passwordHMAC, chp.Password) {
		return nil, errors.New("incorrect password")
	}

	// Check file integrity
	encryption, success := CheckHMAC(chp, argon2KeyForHMAC)
	if !success {
		return nil, errors.New("user may be corrupted")
	}

	// Unmarshal and decrypt the user data using the argon2 key
	argon2Key := userlib.Argon2Key([]byte(password), []byte(username), 16)
	decryptedData := userlib.SymDec(argon2Key, encryption)

	// Create a new User instance and set the loggedIn property to true
	err = json.Unmarshal(decryptedData, userdataptr)
	if err != nil {
		return nil, err
	}
	userdataptr.loggedIn = true

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	if !userdata.loggedIn {
		return errors.New("you're not logged in")
	}

	storageKey, err := ComplexFileUUID(userdata, filename)

	if err != nil {
		return err
	}

	_, ok := userlib.DatastoreGet(storageKey)

	var file File
	var fileptr = &file
	filekey := userlib.Argon2Key(userdata.FileKey, []byte(filename), 16)
	filehmac := userlib.Argon2Key(filekey, []byte(filename), 16)

	fake_f, fake, err := FakeFile(storageKey, filekey, filehmac)

	if ok {
		if err != nil {
			return err
		}
	}

	//fmt.Println("NOT MEEEEEEE")
	//fmt.Println(fake)

	// Create a new content object with the input content and a random UUID
	contentUUID := uuid.New()
	var contentObj Content
	var objptr = &contentObj
	objptr.Plaintext = content
	objptr.Child = uuid.Nil
	fileptr.ContentKey = userlib.RandomBytes(16)
	StarterByte := userlib.RandomBytes(16)
	StarterByte[0] = 0
	StarterByte[1] = 0
	fileptr.StarterByte = StarterByte
	// Encrypt the content with the file's encryption key and compute HMAC
	encryptKey := userlib.Argon2Key(fileptr.ContentKey, StarterByte, 16)
	hmacKey := userlib.Argon2Key(encryptKey, StarterByte, 16)

	//fmt.Println("Store")
	//fmt.Println(StarterByte)

	err = EasySet(contentObj, contentUUID, encryptKey, hmacKey)

	if err != nil {
		return err
	}

	// Update the file's start and end UUIDs
	fileptr.Start = contentUUID
	fileptr.End = contentUUID

	//fmt.Println("So WHYY")
	if fake {
		storageKey, err = FileParent(fake_f.Start, fake_f.ConversionKey, fake_f.ConversionHmac)
		if err != nil {
			return err
		}
		filekey = fake_f.FileKey
		filehmac = fake_f.HMACKey
	}

	//fmt.Println("EEENNNNNDDD")
	//fmt.Println(file.End)
	EasySet(file, storageKey, filekey, filehmac)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	if !userdata.loggedIn {
		return errors.New("you're not logged in")
	}

	// _, err := userdata.LoadFile(filename)

	// if err != nil {
	// 	return err
	// }

	var file File
	var fileptr = &file
	file_uuid, err := ComplexFileUUID(userdata, filename)

	if err != nil {
		return err
	}

	file_key := userlib.Argon2Key(userdata.FileKey, []byte(filename), 16)
	file_hmac := userlib.Argon2Key(file_key, []byte(filename), 16)

	fileptr, err = GetFile(file_uuid, file_key, file_hmac)

	if err != nil {
		return err
	}

	fake_f, fake, err := FakeFile(file_uuid, file_key, file_hmac)

	if err != nil {
		return err
	}
	file = *fileptr

	contentUUID := uuid.New()
	var contentObj Content
	var objptr = &contentObj
	objptr.Plaintext = content
	objptr.Child = uuid.Nil

	//fmt.Println("EEENNNNNDDD")
	//fmt.Println(file.ContentKey)
	//fmt.Println("before")
	//fmt.Println(starter_int)
	//fmt.Println("after")
	//fmt.Println(starter_int)
	curr_byte := file.StarterByte
	num := file.Content_num

	for i := 0; i < num; i++ {
		curr_byte = AddOneToByteArray(curr_byte)
	}

	latest_content_key := userlib.Argon2Key(fileptr.ContentKey, curr_byte, 16)
	latest_content_hmac := userlib.Argon2Key(latest_content_key, curr_byte, 16)
	//fmt.Println("Append")
	//fmt.Println(curr_byte)
	latest_content, err := GetContent(file.End, latest_content_key, latest_content_hmac)
	if err != nil {
		return err
	}
	latest_content.Child = contentUUID

	err = EasySet(*latest_content, file.End, latest_content_key, latest_content_hmac)
	if err != nil {
		return err
	}

	fileptr.End = contentUUID
	// fmt.Println("start")
	// fmt.Println(file.Start)
	// fmt.Println("end")
	// fmt.Println(file.End)

	fileptr.Content_num = file.Content_num + 1
	curr_byte = AddOneToByteArray(curr_byte)

	//fmt.Println("Append second")
	//fmt.Println(curr_byte)

	encryptKey := userlib.Argon2Key(fileptr.ContentKey, curr_byte, 16)
	hmacKey := userlib.Argon2Key(encryptKey, curr_byte, 16)
	err = EasySet(contentObj, contentUUID, encryptKey, hmacKey)
	if err != nil {
		return err
	}
	file = *fileptr

	if fake {
		file_uuid, err = FileParent(fake_f.Start, fake_f.ConversionKey, fake_f.ConversionHmac)
		if err != nil {
			return err
		}
		file_key = fake_f.FileKey
		file_hmac = fake_f.HMACKey
	}

	err = EasySet(file, file_uuid, file_key, file_hmac)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	if !userdata.loggedIn {
		return nil, errors.New("you're not logged in")
	}
	var file File
	var fileptr = &file
	file_uuid, err := ComplexFileUUID(userdata, filename)

	if err != nil {
		return nil, err
	}

	file_key := userlib.Argon2Key(userdata.FileKey, []byte(filename), 16)
	file_hmac := userlib.Argon2Key(file_key, []byte(filename), 16)

	//fmt.Println("Success")

	fileptr, err = GetFile(file_uuid, file_key, file_hmac)

	if err != nil {
		return nil, err
	}

	//fmt.Println("Success")

	curr_uuid := fileptr.Start
	curr_key := fileptr.StarterByte
	content_key := userlib.Argon2Key(fileptr.ContentKey, curr_key, 16)
	content_hmac := userlib.Argon2Key(content_key, curr_key, 16)
	c, err := GetContent(curr_uuid, content_key, content_hmac)
	if err != nil {
		return nil, err
	}
	content = append(content, c.Plaintext...)
	for curr_uuid != uuid.Nil {
		// fmt.Println("uuid")
		// fmt.Println(curr_uuid)
		// fmt.Println(string(content))
		curr_uuid = c.Child
		if curr_uuid == uuid.Nil {
			break
		}
		curr_key = AddOneToByteArray(curr_key)
		content_key = userlib.Argon2Key(fileptr.ContentKey, curr_key, 16)
		content_hmac = userlib.Argon2Key(content_key, curr_key, 16)
		c, err = GetContent(curr_uuid, content_key, content_hmac)
		if err != nil {
			return nil, err
		}
		content = append(content, c.Plaintext...)
	}
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	if !userdata.loggedIn {
		return uuid.Nil, errors.New("you're not logged in")
	}
	var inv Invitation
	var invptr = &inv
	var ch CipherAndHMAC
	var chp = &ch
	var file File
	var fileptr = &file
	var conv Conversion
	var convptr = &conv
	file_uuid, err := ComplexFileUUID(userdata, filename)

	if err != nil {
		return uuid.Nil, err
	}

	//fmt.Println("PAASSSS")

	file_key := userlib.Argon2Key(userdata.FileKey, []byte(filename), 16)
	file_hmac := userlib.Argon2Key(file_key, []byte(filename), 16)

	datastoreValue, found := userlib.DatastoreGet(file_uuid)
	if !found {
		return uuid.Nil, errors.New("file not found")
	}

	_, ok := userlib.KeystoreGet(recipientUsername)

	if !ok {
		return uuid.Nil, errors.New("target user doesn't exist")
	}

	json.Unmarshal(datastoreValue, chp)
	encryptedData, success := CheckHMAC(chp, file_hmac)
	if !success {
		return uuid.Nil, errors.New("file corrupted")
	}
	file_byte := userlib.SymDec(file_key, encryptedData)
	json.Unmarshal(file_byte, fileptr)

	convptr.File_UUID = file_uuid

	convargon := userlib.Argon2Key([]byte(filename), []byte(userdata.Username+string(userdata.Password)+recipientUsername), 16)
	conversion_uuid, err := uuid.FromBytes(convargon)

	if err != nil {
		return uuid.Nil, err
	}

	if fileptr.Fake {
		conversion_uuid = fileptr.Start
		conversion, ok := userlib.DatastoreGet(conversion_uuid)
		if !ok {
			return uuid.Nil, errors.New("access is revoked, give it up")
		}
		json.Unmarshal(conversion, chp)
		encrypt_conversion, success := CheckHMAC(chp, file.ConversionHmac)
		if !success {
			return uuid.Nil, errors.New("conversion corrupted")
		}
		intermediate := userlib.SymDec(fileptr.ConversionKey, encrypt_conversion)
		json.Unmarshal(intermediate, convptr)
		invptr.Conversion_key = fileptr.ConversionKey
		invptr.Conversion_hmac = fileptr.ConversionHmac
		invptr.File_key = fileptr.FileKey
		invptr.HMAC = fileptr.HMACKey
	} else {
		invptr.Conversion_key = userlib.Argon2Key([]byte(filename), userdata.Password, 16)
		invptr.File_key = file_key
		invptr.HMAC = file_hmac
		invptr.Conversion_hmac = userlib.Argon2Key(invptr.Conversion_key, []byte(recipientUsername), 16)
		err = EasySet(conv, conversion_uuid, invptr.Conversion_key, invptr.Conversion_hmac)
		if err != nil {
			return uuid.Nil, err
		}
		sharing, err := FindLstByUUID(userdata, userdata.Shared_Users)

		if err != nil {
			return uuid.Nil, err
		}

		appendValueToMap := func(key string, value string) {
			if arr, found := sharing[key]; found {
				sharing[key] = append(arr, value)
			} else {
				sharing[key] = []string{value}
			}
		}
		appendValueToMap(filename, recipientUsername)

		lst_key := userlib.Argon2Key(userdata.Password, []byte("lst"+userdata.Username), 16)
		lst_hmac := userlib.Argon2Key(lst_key, []byte("lst"+string(userdata.Password)), 16)

		EasySet(sharing, userdata.Shared_Users, lst_key, lst_hmac)
	}
	invargon := userlib.Argon2Key([]byte(filename), []byte(userdata.Username+"inv"+recipientUsername), 16)
	invitationPtr, err = uuid.FromBytes(invargon)

	if err != nil {
		return uuid.Nil, err
	}

	invptr.Conversion_UUID = conversion_uuid
	invP, err := json.Marshal(inv)

	if err != nil {
		return uuid.Nil, err
	}

	rsaKeyHash := userlib.Hash([]byte(recipientUsername))
	rsaKeyString := string(rsaKeyHash[:])
	pub_key, ok := userlib.KeystoreGet(rsaKeyString)

	if !ok {
		return uuid.Nil, errors.New("recipient doesn't exist")
	}

	invencr, key, err := HybridEncryption(pub_key, invP)

	if err != nil {
		return uuid.Nil, err
	}

	chp.CipherText = invencr
	chp.Password = key
	sig, err := userlib.DSSign(userdata.SignKey, invencr)

	if err != nil {
		return uuid.Nil, err
	}

	chp.Signature = sig
	ch_v, err := json.Marshal(ch)

	if err != nil {
		return uuid.Nil, err
	}

	userlib.DatastoreSet(invitationPtr, ch_v)
	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	if !userdata.loggedIn {
		return errors.New("you're not logged in")
	}

	file_uuid, err := ComplexFileUUID(userdata, filename)

	if err != nil {
		return err
	}

	_, ok := userlib.DatastoreGet(file_uuid)

	if ok {
		return errors.New("you already have a file with this name")
	}

	var inv Invitation
	var invptr = &inv
	var ch CipherAndHMAC
	var chp = &ch
	var file File
	var fileptr = &file

	datastoreValue, found := userlib.DatastoreGet(invitationPtr)
	if !found {
		return errors.New("access revoked, give it up")
	}
	json.Unmarshal(datastoreValue, chp)

	pub_key, ok := userlib.KeystoreGet(senderUsername)

	if !ok {
		return errors.New("sender not found")
	}
	err = userlib.DSVerify(pub_key, chp.CipherText, chp.Signature)

	if err != nil {
		return errors.New("failed to verify invitation")
	}

	key, err := userlib.PKEDec(userdata.RSAKey, chp.Password)

	if err != nil {
		return err
	}

	inv_byte := userlib.SymDec(key, chp.CipherText)
	json.Unmarshal(inv_byte, invptr)
	inv = *invptr

	fileptr.Start = inv.Conversion_UUID
	fileptr.ConversionKey = inv.Conversion_key
	fileptr.FileKey = inv.File_key
	fileptr.HMACKey = inv.HMAC
	fileptr.Fake = true
	file.ConversionHmac = inv.Conversion_hmac
	file_key := userlib.Argon2Key(userdata.FileKey, []byte(filename), 16)
	file_hmac := userlib.Argon2Key(file_key, []byte(filename), 16)

	EasySet(file, file_uuid, file_key, file_hmac)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	invi_uuid, err := uuid.FromBytes(userlib.Argon2Key([]byte(filename), []byte(userdata.Username+"inv"+recipientUsername), 16))
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(invi_uuid)
	if !ok {
		return errors.New("no invitation with target")
	}

	userlib.DatastoreDelete(invi_uuid)

	file_uuid, err := ComplexFileUUID(userdata, filename)

	if err != nil {
		return err
	}

	sharing, err := FindLstByUUID(userdata, userdata.Shared_Users)

	if err != nil {
		return err
	}

	arr, found := sharing[filename]

	if (!found) || len(arr) == 0 {
		return errors.New("you didn't share this file with anyone")
	}

	// fmt.Println("THE LIST")
	// fmt.Println(arr)

	deleteValueFromMap := func(key string, valueToDelete string) {
		if arr, found := sharing[key]; found {
			// Key exists, search for the value in the array
			for i, v := range arr {
				if v == valueToDelete {
					// Remove the value from the array using slicing
					sharing[key] = append(arr[:i], arr[i+1:]...)
					return
				}
			}
		}
	}
	deleteValueFromMap(filename, recipientUsername)

	// fmt.Println("THE LIST NOW")
	// fmt.Println(arr)
	// fmt.Println(found)

	arr = sharing[filename]

	//fmt.Println("The map")
	//fmt.Println(sharing)
	//fmt.Println(userdata.Shared_Users)

	r_lst, err := FindNumByUUID(userdata, userdata.Revoked_times)
	if err != nil {
		return err
	}
	_, found = r_lst[filename]

	// fmt.Println("Found or not")
	// fmt.Println(found)

	if !found {
		r_lst[filename] = 1
	} else {
		r_lst[filename] = r_lst[filename] + 1
	}

	// fmt.Println("times")
	// fmt.Println(times)
	// fmt.Println(r_lst[filename])

	lst_key := userlib.Argon2Key(userdata.Password, []byte("lst"+userdata.Username), 16)
	lst_hmac := userlib.Argon2Key(lst_key, []byte("lst"+string(userdata.Password)), 16)

	num_key := userlib.Argon2Key(userdata.Password, []byte("num"+userdata.Username), 16)
	num_hmac := userlib.Argon2Key(num_key, []byte("num"+string(userdata.Password)), 16)

	EasySet(sharing, userdata.Shared_Users, lst_key, lst_hmac)
	EasySet(r_lst, userdata.Revoked_times, num_key, num_hmac)

	var file File
	var fileptr = &file
	var conv Conversion
	var convptr = &conv
	var ch CipherAndHMAC
	var chp = &ch
	file_key := userlib.Argon2Key(userdata.FileKey, []byte(filename), 16)
	file_hmac := userlib.Argon2Key(file_key, []byte(filename), 16)
	fileptr, err = GetFile(file_uuid, file_key, file_hmac)
	file = *fileptr

	userlib.DatastoreDelete(file_uuid)

	file_uuid, _ = uuid.FromBytes(userlib.Argon2Key(userdata.Password, file_uuid[:], 16))

	EasySet(file, file_uuid, file_key, file_hmac)

	if err != nil {
		return err
	}

	convargon := userlib.Argon2Key(userdata.Password, []byte(userdata.Username+"conv"+recipientUsername), 16)
	conversion_uuid, err := uuid.FromBytes(convargon)

	if err != nil {
		return err
	}

	userlib.DatastoreDelete(conversion_uuid)

	for i := 0; i < len(arr); i++ {
		convargon = userlib.Argon2Key([]byte(filename), []byte(userdata.Username+string(userdata.Password)+arr[i]), 16)
		conversion_uuid, _ = uuid.FromBytes(convargon)
		conversion_key := userlib.Argon2Key([]byte(filename), userdata.Password, 16)
		conversion_hmac := userlib.Argon2Key(conversion_key, []byte(arr[i]), 16)
		conversion, ok := userlib.DatastoreGet(conversion_uuid)
		if !ok {
			return errors.New("access is revoked, give it up")
		}
		json.Unmarshal(conversion, chp)
		encrypt_conversion, success := CheckHMAC(chp, conversion_hmac)
		if !success {
			return errors.New("conversion corrupted")
		}
		intermediate := userlib.SymDec(conversion_key, encrypt_conversion)
		json.Unmarshal(intermediate, convptr)
		convptr.File_UUID = file_uuid
		EasySet(conv, conversion_uuid, conversion_key, conversion_hmac)
	}
	return nil
}
