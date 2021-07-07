package drop
import (

	"encoding/json"

	"encoding/hex"

	"github.com/google/uuid"

	"strings"

	"errors"

	_"strconv"

)

func someUsefulThings() {
	f := uuid.New()
	DebugMsg("UUID as string:%v", f.String())

	f[0] = 10
	DebugMsg("UUID as string:%v", f.String())

	h := hex.EncodeToString([]byte("fubar"))
	DebugMsg("The hex: %v", h)

	d, _ := json.Marshal(f)
	DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	DebugMsg("Unmarshaled data %v", g.String())

	DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	var pk PKEEncKey
        var sk PKEDecKey
	pk, sk, _ = PKEKeyGen()
	DebugMsg("Key is %v, %v", pk, sk)
}

func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

type Shared struct {
	Parent [][]byte
	Root bool
	Info [][]byte
}

// The structure definition for a user record
type User struct {
	Username string /* Used to verify the integrity of the User struct. */
	Password string
  PrivateSigningKey DSSignKey /* An asymmetric digital signing key to protect
  the integrity of the user struct */
  PrivateDecryptKey PKEDecKey /* An Asymmetric key generated to decrypt
  information being shared between two individuals */
  FileInformation map[string][][]byte /* A map that is used to store the SharedNode security information */
	SharedWith map[string][]string /* A map that is used to store the different usernames that the user shares
	the file with */
	SharedWithInfo map[string][]byte /* A map that is used to store the child's SharedNode information */

}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	var verifyKey DSVerifyKey
	var encryptKey PKEEncKey

	var userPass []byte = Argon2Key([]byte(password), []byte(username), 16)
	UUID, err := uuid.FromBytes(userPass)
	random_bytes := RandomBytes(16)

	_, takenUsername := KeystoreGet(username + "EK")
	if takenUsername {
		return nil, errors.New(strings.ToTitle("Username already taken"))
	}
	_, takenUsername = KeystoreGet(username + "VK")
	if takenUsername {
		return nil, errors.New(strings.ToTitle("Username already taken"))
	}


	userdata.Username = username
	userdata.Password = password
	userdata.PrivateSigningKey, verifyKey, _ = DSKeyGen()
	encryptKey, userdata.PrivateDecryptKey, _ = PKEKeyGen()
	userdata.FileInformation = make(map[string][][]byte)
	userdata.SharedWith = make(map[string][]string)
	userdata.SharedWithInfo = make(map[string][]byte)

	packaged_data, _ := json.Marshal(userdata)
	store := SymEnc(userPass, random_bytes, packaged_data)
	tempVerify, _ := DSSign(userdata.PrivateSigningKey, store)
	input := append(tempVerify, store...)
	DatastoreSet(UUID, input)

	KeystoreSet(username + "VK", verifyKey)
	KeystoreSet(username + "EK", encryptKey)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	var userPass []byte = Argon2Key([]byte(password), []byte(username), 16)
	uuid, err := uuid.FromBytes(userPass)
	if err != nil {
		return nil, errors.New(strings.ToTitle("UUID failed to generate"))
	}

	verifyKey, keyError := KeystoreGet(username + "VK")
	if (!keyError) {
		return nil, errors.New(strings.ToTitle("Key not found!"))
	}

	received, getError := DatastoreGet(uuid)
	if (!getError) {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	if len(received) < 256 {
		return nil, errors.New(strings.ToTitle("File has been tampered with!"))
	}
	error := DSVerify(verifyKey, received[256:], received[:256])
	if (error != nil) {
		return nil, error
	}
	tempUser := SymDec(userPass, received[256:])
	json.Unmarshal(tempUser, &userdata)

	return userdataptr, nil
}

func (userdata *User) UpdateUser() {
	var userPass []byte = Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	UUID, _ := uuid.FromBytes(userPass)
	random_bytes := RandomBytes(16)
	packaged_data, _ := json.Marshal(userdata)
	store := SymEnc(userPass, random_bytes, packaged_data)
	tempVerify, _ := DSSign(userdata.PrivateSigningKey, store)
	input := append(tempVerify, store...)
	DatastoreSet(UUID, input)
}

func (userdata *User) StoreFile(filename string, data []byte) {
	userdata, userErr := GetUser(userdata.Username, userdata.Password);
	if userErr != nil {
			return
	}
	var sharedNode Shared
	fileUUID_bytes := RandomBytes(16)
	fileUUID, _ := uuid.FromBytes(fileUUID_bytes)
	sym_key := RandomBytes(AESKeySize)
	iv := RandomBytes(AESBlockSize)
	mac_key := RandomBytes(16)

	sym_enc_data := SymEnc(sym_key, iv, data)
	enc_mac_data, _ := HMACEval(mac_key, sym_enc_data)
	DatastoreSet(fileUUID, append(enc_mac_data, sym_enc_data...))

	info, fileOk := userdata.FileInformation[filename]
	var sharedUUID_bytes, shared_sym_key, shared_iv, shared_mac_key []byte
	var sharedUUID uuid.UUID
	if !fileOk {
		sharedUUID_bytes = RandomBytes(16)
		sharedUUID, _ = uuid.FromBytes(sharedUUID_bytes)
		shared_sym_key = RandomBytes(AESKeySize)
		shared_iv = RandomBytes(AESBlockSize)
		shared_mac_key = RandomBytes(16)
	} else {
		sharedUUID_bytes = info[0]
		sharedUUID, _ = uuid.FromBytes(sharedUUID_bytes)
		shared_iv = RandomBytes(16)
		shared_sym_key = info[1]
		shared_mac_key = info[2]
		for {
			sharedRes, getShared := DatastoreGet(sharedUUID)
			if !getShared  || len(sharedRes) < 64 {
				return
			}
			sharedChecker, sharedErr := HMACEval(shared_mac_key, sharedRes[64:])
			if (sharedErr != nil || !HMACEqual(sharedRes[:64], sharedChecker)) {
				return
			}
			sharedTemp := SymDec(shared_sym_key, sharedRes[64:])
			json.Unmarshal(sharedTemp, &sharedNode)
			if sharedNode.Root && sharedNode.Parent == nil {
				break;
			}
			if sharedNode.Info == nil && sharedNode.Parent == nil {
				return
			}
			sharedUUID_bytes = sharedNode.Parent[0]
			sharedUUID, _ = uuid.FromBytes(sharedUUID_bytes)
			shared_sym_key = sharedNode.Parent[1]
			shared_mac_key = sharedNode.Parent[2]
		}
	}
	item := append(append(fileUUID_bytes, sym_key...), mac_key...)
	// shared_item := append(append(sharedUUID_bytes, shared_sym_key...), shared_mac_key...)
	userdata.FileInformation[filename] = [][]byte{sharedUUID_bytes, shared_sym_key, shared_mac_key}

	sharedNode.Info = [][]byte{item}
	sharedNode.Root = true
	sharedNode.Parent = nil
	sharedInfo, _ := json.Marshal(sharedNode)

	shared_sym_enc_data := SymEnc(shared_sym_key, shared_iv, sharedInfo)
	shared_enc_mac_data, _ := HMACEval(shared_mac_key, shared_sym_enc_data)
	DatastoreSet(sharedUUID, append(shared_enc_mac_data, shared_sym_enc_data...))

	userdata.UpdateUser()

	return
}

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	userdata, userErr := GetUser(userdata.Username, userdata.Password);
	if userErr != nil {
			return userErr
	}
	info, fileOk := userdata.FileInformation[filename]
	if !fileOk {
		return errors.New(strings.ToTitle("File does not exist."))
	}

	var sharedNode Shared
	sharedUUID_bytes := info[0]
	sharedUUID, _ := uuid.FromBytes(sharedUUID_bytes)
	shared_iv := RandomBytes(16)
	shared_sym_key := info[1]
	shared_mac_key := info[2]
	for {
		sharedRes, getShared := DatastoreGet(sharedUUID)
		if !getShared {
			return errors.New(strings.ToTitle("File does not exist in Datastore."))
		}
		if (len(sharedRes) < 64) {
			return errors.New(strings.ToTitle("Invalid file."))
		}
		sharedChecker, sharedErr := HMACEval(shared_mac_key, sharedRes[64:])
		if (sharedErr != nil || !HMACEqual(sharedRes[:64], sharedChecker)) {
			return errors.New(strings.ToTitle("sharedUUID: HMAC is invalid."))
		}
		sharedTemp := SymDec(shared_sym_key, sharedRes[64:])
		json.Unmarshal(sharedTemp, &sharedNode)
		if sharedNode.Root && sharedNode.Parent == nil {
			break;
		}
		if sharedNode.Info == nil && sharedNode.Parent == nil {
			return errors.New(strings.ToTitle("Rip"))
		}
		sharedUUID_bytes = sharedNode.Parent[0]
		sharedUUID, _ = uuid.FromBytes(sharedUUID_bytes)
		shared_sym_key = sharedNode.Parent[1]
		shared_mac_key = sharedNode.Parent[2]
	}

	fileUUID_bytes := RandomBytes(16)
	fileUUID, _ := uuid.FromBytes(fileUUID_bytes)
	sym_key := RandomBytes(AESKeySize)
	iv := RandomBytes(AESBlockSize)
	mac_key := RandomBytes(16)

	sharedNode.Info = append(sharedNode.Info, append(append(fileUUID_bytes, sym_key...), mac_key...) )
	sharedInfo, _ := json.Marshal(sharedNode)
	// Encrypt then HMAC the sharedNode then put into Datastore
	shared_sym_enc_data := SymEnc(shared_sym_key, shared_iv, sharedInfo)
	shared_enc_mac_data, _ := HMACEval(shared_mac_key, shared_sym_enc_data)
	DatastoreSet(sharedUUID, append(shared_enc_mac_data, shared_sym_enc_data...))

	sym_enc_data := SymEnc(sym_key, iv, data)
	enc_mac_data, _ := HMACEval(mac_key, sym_enc_data)
	DatastoreSet(fileUUID, append(enc_mac_data, sym_enc_data...))

	return nil
}

func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	userdata, userErr  := GetUser(userdata.Username, userdata.Password)
	if userErr != nil {
		return nil, userErr
	}
	info, fileOk := userdata.FileInformation[filename]
	if !fileOk {
		return nil, errors.New(strings.ToTitle("File does not exist."))
	}
	var content []byte

	var sharedNode Shared
	sharedUUID_bytes := info[0]
	sharedUUID, _ := uuid.FromBytes(sharedUUID_bytes)
	shared_sym_key := info[1]
	shared_mac_key := info[2]
	for {
		sharedRes, getShared := DatastoreGet(sharedUUID)
		if !getShared {
			delete(userdata.FileInformation, filename)
			userdata.UpdateUser()
			return nil, errors.New(strings.ToTitle("File does not exist in Datastore."))
		}
		if len(sharedRes) < 64 {
			delete(userdata.FileInformation, filename)
			userdata.UpdateUser()
			return nil, errors.New(strings.ToTitle("File is invalid."))
		}
		sharedChecker, sharedErr := HMACEval(shared_mac_key, sharedRes[64:])
		if (sharedErr != nil || !HMACEqual(sharedRes[:64], sharedChecker)) {
			delete(userdata.FileInformation, filename)
			userdata.UpdateUser()
			return nil, errors.New(strings.ToTitle("HMAC is invalid."))
		}
		sharedTemp := SymDec(shared_sym_key, sharedRes[64:])
		json.Unmarshal(sharedTemp, &sharedNode)
		if sharedNode.Root && sharedNode.Parent == nil && sharedNode.Info != nil {
			break;
		}
		if sharedNode.Info == nil && sharedNode.Parent == nil {
			return nil,errors.New(strings.ToTitle("Rip"))
		}
		sharedUUID_bytes = sharedNode.Parent[0]
		sharedUUID, _ = uuid.FromBytes(sharedUUID_bytes)
		shared_sym_key = sharedNode.Parent[1]
		shared_mac_key = sharedNode.Parent[2]
	}

	for _, item := range sharedNode.Info {
		fileUUID, _ := uuid.FromBytes(item[:16])
		sym_key := item[16:32]
		mac_key := item[32:]
		result, ok := DatastoreGet(fileUUID)
		if !ok {
			delete(userdata.FileInformation, filename)
			userdata.UpdateUser()
			return nil, errors.New(strings.ToTitle("File does not exist."))
		}
		if len(result) < 64 {
			delete(userdata.FileInformation, filename)
			userdata.UpdateUser()
			return nil, errors.New(strings.ToTitle("File has been tampered with."))
		}
		// Verify that the file's content has not been tampered with
		checker, err := HMACEval(mac_key, result[64:])
		if (err != nil || !HMACEqual(result[:64], checker)) {
			delete(userdata.FileInformation, filename)
			userdata.UpdateUser()
			return nil, errors.New(strings.ToTitle("File HMAC is invalid."))
		}
		content = append(content, SymDec(sym_key, result[64:])...)
	}
	return content, nil
}

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	userdata, userErr  := GetUser(userdata.Username, userdata.Password)
	if userErr != nil {
		return "", userErr
	}
	_, loadErr := userdata.LoadFile(filename)
	if loadErr != nil {
		return "", errors.New(strings.ToTitle("File is invalid"))
	}
	// Get public encryption key from Keystore
	encryptKey, getEk := KeystoreGet(recipient + "EK")
	if !getEk {
		return "", errors.New(strings.ToTitle("Unable to get recipient's encryption key"))
	}
	// Get file information from userdata.FileInformation
	info, fileOk := userdata.FileInformation[filename]
	if !fileOk {
		return "", errors.New(strings.ToTitle("File does not exist for this user."))
	}

	userUUID_bytes := info[0]
	user_sym_key := info[1]
	user_mac_key := info[2]

	// Create and Marshall sharedNode
	var sharedNode Shared
	sharedNode.Parent = [][]byte{userUUID_bytes, user_sym_key, user_mac_key}
	sharedNode.Root = false
	sharedNode.Info = nil
	combinedInfo, _ := json.Marshal(sharedNode)

	sharedUUID_bytes := RandomBytes(16)
	sharedUUID, _ := uuid.FromBytes(sharedUUID_bytes)
	shared_sym_key := RandomBytes(AESKeySize)
	shared_iv := RandomBytes(AESBlockSize)
	shared_mac_key := RandomBytes(16)

	// Encrypt and sign the sharedNode
	shared_sym_enc_data := SymEnc(shared_sym_key, shared_iv, combinedInfo)
	shared_enc_mac_data, _ := HMACEval(shared_mac_key, shared_sym_enc_data)
	DatastoreSet(sharedUUID, append(shared_enc_mac_data, shared_sym_enc_data...))

	// Store encrypted sharedNode under sharedUUID
	DatastoreSet(sharedUUID, append(shared_enc_mac_data, shared_sym_enc_data...))

	// Create magic_string
	sharedInfo := append(append(sharedUUID_bytes, shared_sym_key...), shared_mac_key...)
	// Encrypt and sign the sharedUUID
	magicEncrypt, magicEncryptErr := PKEEnc(encryptKey, sharedInfo)
	if magicEncryptErr != nil {
		return "", errors.New(strings.ToTitle("Unable to encrypt shared"))
	}
	magicSigned, magicSignErr := DSSign(userdata.PrivateSigningKey, magicEncrypt)
	if magicSignErr != nil {
		return "", errors.New(strings.ToTitle("Unable to sign shared"))
	}

	userdata.SharedWith[filename] = append(userdata.SharedWith[filename], recipient)
	userdata.SharedWithInfo[recipient + filename] = sharedInfo

	userdata.UpdateUser()

	return string(append(magicSigned, magicEncrypt...)), nil
}
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	userdata, userErr  := GetUser(userdata.Username, userdata.Password)
	if userErr != nil {
		return userErr
	}
	if (magic_string == "" || len(magic_string) < 256) {
		return errors.New(strings.ToTitle("magic_string is empty"))
	}

	rVerifyKey, getVk := KeystoreGet(sender + "VK")
	if !getVk {
		return errors.New(strings.ToTitle("No Verification Key available"))
	}

	magic_bytes := []byte(magic_string)
	if len(magic_bytes) < 256 {
		return errors.New(strings.ToTitle("The magic_string is not from the correct user: Length"))
	}
	magicError := DSVerify(rVerifyKey, magic_bytes[256:], magic_bytes[:256])
	if magicError != nil {
		return errors.New(strings.ToTitle("Signature is invalid"))
	}
	decryptMagic, magicErr := PKEDec(userdata.PrivateDecryptKey, magic_bytes[256:])
	if magicErr != nil {
		return errors.New(strings.ToTitle("Unable to decrypt the magic_string"))
	}

	sharedUUID_bytes := decryptMagic[:16]
	sharedUUID, _ := uuid.FromBytes(sharedUUID_bytes)
	shared_sym_key := decryptMagic[16:32]
	shared_mac_key := decryptMagic[32:]

	file_bytes, okGet := DatastoreGet(sharedUUID)
	if !okGet {
		return errors.New(strings.ToTitle("Unable to retrieve file information"))
	}
	if len(file_bytes) < 64 {
		return errors.New(strings.ToTitle("File has been tampered with"))
	}
	sharedChecker, sharedErr := HMACEval(shared_mac_key, file_bytes[64:])
	if (sharedErr != nil || !HMACEqual(file_bytes[:64], sharedChecker)) {
		return errors.New(strings.ToTitle("HMAC is invalid."))
	}

	_, fileOk := userdata.FileInformation[filename]
	if (fileOk) {
		return errors.New(strings.ToTitle("Multiple files with the same name"))
	}

	userdata.FileInformation[filename] = [][]byte{sharedUUID_bytes, shared_sym_key, shared_mac_key}

	userdata.UpdateUser()
	return nil
}

func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	userdata, userErr  := GetUser(userdata.Username, userdata.Password)
	if userErr != nil {
		return userErr
	}
	info, fileOk := userdata.FileInformation[filename]
	if !fileOk {
		return errors.New(strings.ToTitle("File does not exist."))
	}

	var sharedNode Shared
	oldUUID_bytes := info[0]
	oldUUID, _ := uuid.FromBytes(oldUUID_bytes)
	old_sym_key := info[1]
	old_mac_key := info[2]

	content, loadErr := userdata.LoadFile(filename)
	if loadErr != nil {
		return loadErr
	}

	rootInfo, getRoot := DatastoreGet(oldUUID)
	if !getRoot {
		return errors.New(strings.ToTitle("SharedNode does not exist"))
	}

	if len(rootInfo) < 64  {
		return errors.New(strings.ToTitle("File has been tampered with."))
	}

	sharedChecker, sharedErr := HMACEval(old_mac_key, rootInfo[64:])
	if (sharedErr != nil || !HMACEqual(rootInfo[:64], sharedChecker)) {
		return errors.New(strings.ToTitle("HMAC is invalid."))
	}
	sharedTemp := SymDec(old_sym_key, rootInfo[64:])
	json.Unmarshal(sharedTemp, &sharedNode)

	if !sharedNode.Root {
		return errors.New(strings.ToTitle("Must be creator to revoke."))
	}

	for _, item := range sharedNode.Info {
		fileUUID, _ := uuid.FromBytes(item[:16])

		DatastoreDelete(fileUUID)
		_, ok := DatastoreGet(fileUUID)
		if ok {
			return errors.New(strings.ToTitle("Did not delete file from Datastore"))
		}
	}

	DatastoreDelete(oldUUID)
	_, ok := DatastoreGet(oldUUID)
	if ok {
		return errors.New(strings.ToTitle("Did not delete old sharedNode"))
	}

	fileUUID_bytes := RandomBytes(16)
	fileUUID, _ := uuid.FromBytes(fileUUID_bytes)
	sym_key := RandomBytes(AESKeySize)
	iv := RandomBytes(AESBlockSize)
	mac_key := RandomBytes(16)

	sym_enc_data := SymEnc(sym_key, iv, content)
	enc_mac_data, _ := HMACEval(mac_key, sym_enc_data)
	DatastoreSet(fileUUID, append(enc_mac_data, sym_enc_data...))

	item := append(append(fileUUID_bytes, sym_key...), mac_key...)
	var newNode Shared
	newNode.Info = [][]byte{item}
	newNode.Root = true
	newNode.Parent = nil
	sharedInfo, _ := json.Marshal(newNode)

	sharedUUID_bytes := RandomBytes(16)
	sharedUUID, _ := uuid.FromBytes(sharedUUID_bytes)
	shared_sym_key := RandomBytes(AESKeySize)
	shared_iv := RandomBytes(AESBlockSize)
	shared_mac_key := RandomBytes(16)

	userdata.FileInformation[filename] = [][]byte{sharedUUID_bytes, shared_sym_key, shared_mac_key}
	shared_sym_enc_data := SymEnc(shared_sym_key, shared_iv, sharedInfo)
	shared_enc_mac_data, _ := HMACEval(shared_mac_key, shared_sym_enc_data)
	DatastoreSet(sharedUUID, append(shared_enc_mac_data, shared_sym_enc_data...))
	var newSharedWith []string
	found := false
	for _, user := range userdata.SharedWith[filename] {
		sInfo, exist := userdata.SharedWithInfo[user + filename]
		if !exist {
			return errors.New(strings.ToTitle(user + " does not have access to file already"))
		}
		updateUUID_bytes := sInfo[:16]
		updateUUID, _ := uuid.FromBytes(updateUUID_bytes)
		if user != target_username {
			newSharedWith = append(newSharedWith, user)
			var newNodeChild Shared
			newNodeChild.Info = nil
			newNodeChild.Root = false
			newNodeChild.Parent = [][]byte{sharedUUID_bytes, shared_sym_key, shared_mac_key}
			sharedInfoChild, _ := json.Marshal(newNodeChild)

			update_iv := RandomBytes(AESBlockSize)
			update_sym_key := sInfo[16:32]
			update_mac_key := sInfo[32:]
			update_sym_enc_data := SymEnc(update_sym_key, update_iv, sharedInfoChild)
			update_enc_mac_data, _ := HMACEval(update_mac_key, update_sym_enc_data)
			DatastoreSet(updateUUID, append(update_enc_mac_data, update_sym_enc_data...))
		} else {
			DatastoreDelete(updateUUID)
			found = true;
			delete(userdata.SharedWithInfo, target_username + filename)
		}
	}
	if !found {
		return errors.New(strings.ToTitle(target_username + " does not have access to file already"))
	}
	userdata.SharedWith[filename] = newSharedWith
	userdata.UpdateUser()
	return nil
}
