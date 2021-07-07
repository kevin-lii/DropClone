package drop

import (
	"testing"
	"reflect"
	_ "encoding/json"
	_ "encoding/hex"
	"github.com/google/uuid"
	"strings"
	_ "errors"
	_ "strconv"
)

func clear() {
	DatastoreClear()
	KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	t.Log("Got user", u)

	b, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to grab correct user", err)
		return
	}
	t.Log("Got user", b)

	_, err = GetUser("alice", "wrong fucking password bitch")
	if err == nil {
		t.Error("Malicious user used different pswd to login")
		return
	}

	_, err = GetUser("bob", "fubar")
	if err == nil {
		t.Error("Got a nonexistent user")
		return
	}
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	t.Log("Serialized message", v)
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a nonexistent file", err2)
		return
	}
}


func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "fubar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	// try to share w/ nonexistent user
	_, err = u.ShareFile("file1", "kevin")
	if err == nil {
		t.Error("Shared file with uninitialized user")
		return
	}
	// try to share nonexistent file
	_, err = u.ShareFile("this don't exist", "bob")
	if err == nil {
		t.Error("Shared nonexistent file")
		return
	}
	// non-existent user + non-existent file
	_, err = u.ShareFile("wha", "wha")
	if err == nil {
		t.Error("Shared non-existent file with non-existent user")
		return
	}
}

func TestRevokeSimple(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err3 := InitUser("kevin", "bruhmoment")
	if err3 != nil {
		t.Error("Failed to initialize kevin", err3)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var magic_string string

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "kevin")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	// Revoke kevin's access to alice's file
	err = u.RevokeFile("file1", "kevin")
	if err != nil {
		t.Error("Failed to revoke access to file", err)
		return
	}
	// alice makes changes to the file
	v2 := []byte("Changed file contents")
	u.StoreFile("file1", v2)
	// kevin tries to access file again
	v, err = u3.LoadFile("file2")
	// checks if kevin still has access to updated file
	if reflect.DeepEqual(v, v2) {
		t.Error("Revoked user can access shared changes", v, v2)
		return
	}
	if err == nil {
		t.Error("Revoked user can still access file")
	}
	// kevin tries to share the file
	magic_string, err = u3.ShareFile("file2", "bob")
	if err == nil {
		t.Error("Revoked user can still share the file", err)
		return
	}
	// bob should still be able to access the file
	v, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Still shared user failed to download the file from alice", err)
		return
	}
	// revoke twice --> error
	err = u.RevokeFile("file1", "kevin")
	if err == nil {
		t.Error("Revoked nonshared file")
		return
	}
	// revoke nonexistent file --> should error
	err = u.RevokeFile("doesn't exist", "bob")
	if err == nil {
		t.Error("Revoked nonexistent file")
	}
}

func TestAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test. ")
	u.StoreFile("file1", v)

	var magic_string string
	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	u2.ReceiveFile("file2", "alice", magic_string)

	v, err = u.LoadFile("file1")
	v2 := []byte("This is the appended message.")
	err = u.AppendFile("file1", v2)
	if err != nil {
		t.Error("Failed to append to file", err)
		return
	}

	v3 := []byte("Shouldn't be appended")
	err = u.AppendFile("file69", v3)
	if err == nil {
		t.Error("Appended to nonexistent file")
	}

	v = append(v, v2...)
	v2, err = u.LoadFile("file1")

	if !reflect.DeepEqual(v, v2) {
		t.Error("File did not receive appended changes", v, v2)
		return
	}
	// bob should immediately see the appended changes
	v2, err = u2.LoadFile("file2")
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared user cannot see appended changes", v, v2)
		return
	}
}

func TestMultipleInstantiationsOfUser(t *testing.T) {
	clear()
	InitUser("alice", "fubar")
	a, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to grab correct user", err)
		return
	}
	b, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to grab correct user", err)
		return
	}

	v := []byte("This is a test")
	a.StoreFile("file1", v)
	// b must be able to immediately download file
	v2, err := b.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	// b must be able to see appended changes
	v2 = []byte("This is the appended message.")
	a.AppendFile("file1", v2)

	v = append(v, v2...)
	v2, err = b.LoadFile("file1")

	if !reflect.DeepEqual(v, v2) {
		t.Error("File did not receive appended changes", v, v2)
		return
	}
	// after a receives a file, b must be able to download it
	u2, _ := InitUser("bob", "foobar")
	v3 := []byte("poo poo pee pee")
	u2.StoreFile("bobfile", v3)
	magic_string, err := u2.ShareFile("bobfile", "alice")

	a.ReceiveFile("file2", "bob", magic_string)

	_, err = b.LoadFile("file2")
	if err != nil {
		t.Error("Other user instance cannot access shared file", err)
		return
	}
}

func TestSharingTree(t *testing.T) {
	// if a shares with b and c, and b shares with d, then changes made by
	// a, b, c, and d should be visible to everyone
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "foobar")
	c, _ := InitUser("cathy", "poobar")
	d, _ := InitUser("dan", "peebar")

	v := []byte("This is a test")
	a.StoreFile("file1", v)

	magic_string, _ := a.ShareFile("file1", "bob")
	b.ReceiveFile("file1", "alice", magic_string)

	magic_string, _ = a.ShareFile("file1", "cathy")
	c.ReceiveFile("file1", "alice", magic_string)

	magic_string, _ = b.ShareFile("file1", "dan")
	d.ReceiveFile("file1", "bob", magic_string)

	// changes made by alice should be visible to everyone
	v1 := []byte("change by alice")
	a.StoreFile("file1", v1)

	b_check, _ := b.LoadFile("file1")
	if !reflect.DeepEqual(v1, b_check) {
		t.Error("Changes by A are not visible by B", v1, b_check)
		return
	}
	c_check, _ := c.LoadFile("file1")
	if !reflect.DeepEqual(v1, c_check) {
		t.Error("Changes by A are not visible by C", v1, c_check)
		return
	}
	d_check, _ := d.LoadFile("file1")
	if !reflect.DeepEqual(v1, d_check) {
		t.Error("Changes by A are not visible by D", v1, d_check)
		return
	}
	// changes made by bob should be visible to everyone
	v2 := []byte("change by bob")
	b.StoreFile("file1", v2)

	a_check, _ := a.LoadFile("file1")
	if !reflect.DeepEqual(v2, a_check) {
		t.Error("Changes by A are not visible by B", v2, a_check)
		return
	}
	c_check, _ = c.LoadFile("file1")
	if !reflect.DeepEqual(v2, c_check) {
		t.Error("Changes by A are not visible by C", v2, c_check)
		return
	}
	d_check, _ = d.LoadFile("file1")
	if !reflect.DeepEqual(v2, d_check) {
		t.Error("Changes by A are not visible by D", v2, d_check)
		return
	}

	// changes made by cathy should be visible to everyone
	v3 := []byte("change by cathy")
	c.StoreFile("file1", v3)

	a_check, _ = a.LoadFile("file1")
	if !reflect.DeepEqual(v3, a_check) {
		t.Error("Changes by A are not visible by B", v3, a_check)
		return
	}
	b_check, _ = b.LoadFile("file1")
	if !reflect.DeepEqual(v3, b_check) {
		t.Error("Changes by A are not visible by C", v3, b_check)
		return
	}
	d_check, _ = d.LoadFile("file1")
	if !reflect.DeepEqual(v3, d_check) {
		t.Error("Changes by A are not visible by D", v3, d_check)
		return
	}

	// changes made by dan should be visible to everyone
	v4 := []byte("change by dan")
	d.StoreFile("file1", v4)

	a_check, _ = a.LoadFile("file1")
	if !reflect.DeepEqual(v4, a_check) {
		t.Error("Changes by A are not visible by B", v4, a_check)
		return
	}
	b_check, _ = b.LoadFile("file1")
	if !reflect.DeepEqual(v4, b_check) {
		t.Error("Changes by A are not visible by C", v4, b_check)
		return
	}
	c_check, _ = c.LoadFile("file1")
	if !reflect.DeepEqual(v4, c_check) {
		t.Error("Changes by A are not visible by D", v4, c_check)
		return
	}
}

func TestRevokeTree(t *testing.T) {
	// if a shares with b and c, and b shares with d,
	// then if a revokes b's access, d should also not have access
	// while c still would have access because it's not in the same tree
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "foobar")
	c, _ := InitUser("cathy", "poobar")
	d, _ := InitUser("dan", "peebar")

	v := []byte("This is a test")
	a.StoreFile("file1", v)

	magic_string, _ := a.ShareFile("file1", "bob")
	b.ReceiveFile("file1", "alice", magic_string)

	magic_string, _ = a.ShareFile("file1", "cathy")
	c.ReceiveFile("file1", "alice", magic_string)

	magic_string, _ = b.ShareFile("file1", "dan")
	d.ReceiveFile("file1", "bob", magic_string)

	/*err := a.RevokeFile("file1", "dan")
	if err == nil {
		t.Error("Revoked file for nondirect child")
		return
	}*/

	// revoke file for bob (and effectively dan)
	a.RevokeFile("file1", "bob")
	// check if b and d have access (they shouldn't)
	check, _ := b.LoadFile("file1")
	if reflect.DeepEqual(v, check) {
		t.Error("B still has access to the file", v, check)
		return
	}
	check, _ = d.LoadFile("file1")
	if reflect.DeepEqual(v, check) {
		t.Error("D still has access to the file", v, check)
		return
	}
	// c should still have access to the shared file
	check, _ = c.LoadFile("file1")
	if !reflect.DeepEqual(v, check) {
		t.Error("C does not have access to the file", v, check)
		return
	}
}

func TestEmptyFile(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	v := []byte("")
	a.StoreFile("", v)
	_, err := a.LoadFile("")
	if err != nil {
		t.Error("Couldn't store empty file", err)
		return
	}
}

func TestMaliciousUserChange(t *testing.T) {
	clear()
	InitUser("alice", "fubar")
	datastore_map := DatastoreGetMap()

	for key, value := range datastore_map {
		datastore_map[key] = RandomBytes(len(value))
	}

	_, err := GetUser("alice", "fubar")
	if err == nil {
		t.Error("Malicious user received")
		return
	}
}

func TestChangingMagicString(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "foobar")
	InitUser("cathy", "poop")
	v := []byte("This is a test")

	a.StoreFile("file1", v)
	magic_string, err := a.ShareFile("file1", "bob")
	magic_string = string(RandomBytes(len(magic_string)))
	err = b.ReceiveFile("file1", "alice", magic_string)
	if err == nil {
		t.Error("bob received a malicious magic string", err)
		return
	}
	// trying to receive file using wrong magic_string
	// (important test --> worth 2.0 pts)
	magic_string, err = a.ShareFile("file1", "cathy")
	err = b.ReceiveFile("file1", "alice", magic_string)
	if err == nil {
		t.Error("Received file using someone else's access token")
		return
	}


}

func TestMaliciousFile(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "foobar")
	v := []byte("This is a test")

	a.StoreFile("file1", v)
	magic_string, _ := a.ShareFile("file1", "bob")

	b.ReceiveFile("file2", "alice", magic_string)

	datastore_map := DatastoreGetMap()

	for key, value := range datastore_map {
		datastore_map[key] = RandomBytes(len(value))
	}

	_, err := b.LoadFile("file2")
	if err == nil {
		t.Error("Malicious file opened")
		return
	}

	err = a.AppendFile("file1", []byte("shouldn't be added"))
	if err == nil {
		t.Error("Append shouldn't work on corrupted file")
	}
}

func TestDeleteUser(t *testing.T) {
	clear()
	InitUser("alice", "fubar")

	datastore_map := DatastoreGetMap()
	for key, _ := range datastore_map {
		delete(datastore_map, key)
	}
	_, err := GetUser("alice", "fubar")
	if err == nil {
		t.Error("User can still access user data after deletion")
		return
	}
}

func TestSwapUsers(t *testing.T) {
	clear()
	InitUser("alice", "fubar")

	datastore_map := DatastoreGetMap()
	var alice uuid.UUID
	var alice_val []byte
	var count int = 0
	// should only have 1 key-value pair in datastore
	for key, value := range datastore_map {
		alice = key
		alice_val = value
		t.Log("Should only appear once")
		count = count + 1
	}
	t.Log(count) // should be 1
	InitUser("bob", "poobar")
	var count2 int = 0
	for key, value := range datastore_map {
		// should only happen once
		if key != alice {
			datastore_map[key] = alice_val
			datastore_map[alice] = value
			t.Log("Should only appear once")
		}
		count2 = count2 + 1
	}
	t.Log(count2) // should be 2

	_, err := GetUser("alice", "fubar")
	if err == nil {
		t.Error("Malicious swap succeeded")
		return
	}
}

func TestCorruptFiles(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "foobar")
	b, _ := InitUser("bob", "poop")
	datastore_map := DatastoreGetMap()
	var users []uuid.UUID
	//var alice_val []byte
	// should only have 1 key-value pair in datastore
	for key, _ := range datastore_map {
		users = append(users, key)
		//alice_val = value
	}
	t.Log(len(users))

	v := []byte("This is a test")
	a.StoreFile("file1", v)
	b.StoreFile("bobfile", v)

	for key, value := range datastore_map {
		if (key != users[0] && key != users[1]) {
			datastore_map[key] = RandomBytes(len(value))
		}
	}

	err := a.AppendFile("file1", []byte("another append?"))
	if err == nil {
		t.Error("append shouldn't work?")
		return
	}

	_, err = a.LoadFile("file1")
	if err == nil {
		t.Error("Alice is accessing corrupted file")
		return
	}

	_, err = b.LoadFile("bobfile")
	if err == nil {
		t.Error("Bob is accessing corrupted file")
		return
	}

	/*_, err = a.ShareFile("file1", "bob")
	if err == nil {
		t.Error("Share shouldn't work")
		return
	}*/

	/*err = a.RevokeFile("file1", "bob")
	if err == nil {
		t.Error("revoke shouldn't work")
		return
	}*/
}

/*func TestSwapFiles(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "foobar")
	datastore_map := DatastoreGetMap()
	var alice uuid.UUID
	//var alice_val []byte
	// should only have 1 key-value pair in datastore
	for key, _ := range datastore_map {
		alice = key
		//alice_val = value
	}

	v := []byte("This is a test")
	a.StoreFile("file1", v)

	var a_file uuid.UUID
	var a_file_val []byte

	for key, value := range datastore_map {
		if key != alice {
			a_file = key
			a_file_val = value
		}
	}

	b, _ := InitUser("bob", "poop")

	var bob uuid.UUID
	//var bob_val []byte

	for key, _ := range datastore_map {
		if (key != alice && key != a_file) {
			bob = key
			//bob_val = value
		}
	}

	b.StoreFile("bobfile", v)

	for key, value := range datastore_map {
		if (key != alice && key != a_file && key != bob) {
			datastore_map[key] = a_file_val
			datastore_map[a_file] = value
		}
	}

	_, err := a.LoadFile("file1")
	if err == nil {
		t.Error("Alice is accessing swapped file")
		return
	}

	_, err = b.LoadFile("bobfile")
	if err == nil {
		t.Error("Bob is accessing swapped file")
		return
	}
}*/

func TestPUBLICRevoke(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "poop")
	c, _ := InitUser("cathy", "cumfart")

	v := []byte("This is a test")
	a.StoreFile("file1", v)

	magic_string, _ := a.ShareFile("file1", "bob")
	b.ReceiveFile("file1", "alice", magic_string)

	magic_string, _ = a.ShareFile("file1", "cathy")
	c.ReceiveFile("file1", "alice", magic_string)

	a.RevokeFile("file1", "bob")
	v2 := []byte("appended changes")
	err := a.AppendFile("file1", v2)
	if err != nil {
		t.Error("Failed to append after revoking", err)
	}

	// check non-revoked user can see updates
	appended := append(v, v2...)
	check, _ := c.LoadFile("file1")
	if !reflect.DeepEqual(appended, check) {
		t.Error("Incorrect loaded data", appended, check)
		return
	}

	check, _ = a.LoadFile("file1")
	if !reflect.DeepEqual(appended, check) {
		t.Error("Revoker loaded data is incorrect", appended, check)
		return
	}

	// revoked user trying to append file
	b.AppendFile("file1", v2)
	check, _ = a.LoadFile("file1")
	if !reflect.DeepEqual(appended, check) {
		t.Error("Revoker can see revoked user's append", appended, check)
		return
	}
	v1 := []byte("This is another file")
	a.StoreFile("file2", v1)
	magic_string_2, _ := a.ShareFile("file2", "bob")
	recvErr := b.ReceiveFile("file1", "alice", magic_string_2)
	if recvErr == nil {
		t.Error("Multiple file names with same name")
		return
	}
	_, magic_err := a.ShareFile("file3", "bob")
	if magic_err == nil {
		t.Error("File should not exist")
		return
	}
	revoke_err := a.RevokeFile("asdf", "bob")
	if revoke_err == nil {
		t.Error("File does not exist")
		return
	}
	v3 := []byte("This is the final file")
	a.StoreFile("file3", v3)
	revoke_err_2 := a.RevokeFile("file3", "bob")
	if revoke_err_2 == nil {
		t.Error("Not shared to that user")
		return
	}
}

/*func TestNondeterministicTest(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	datastore_map := DatastoreGetMap()


	v := []byte("This is a test")
	a.StoreFile("file1", v)

	b, _ := InitUser("bob", "foobar")
	b.StoreFile("file1", v)

	var change bool = false

	for key, value := range datastore_map {
		if change {
			datastore_map[key] = RandomBytes(len(value))
		}
		change = !change
	}
}*/


func TestShareFileWithSameName(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "foobar")
	v := []byte("This is a test")
	a.StoreFile("file1", v)
	b.StoreFile("file2", v)
	mg_str, _ := a.ShareFile("file1", "bob")
	err := b.ReceiveFile("file2", "alice", mg_str)
	if err == nil {
		t.Error("received file with same name as other file")
		return
	}
}

func TestReceiveFileOnWrongFile(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "foobar")
	v := []byte("This is a test")
	a.StoreFile("file1", v)
	b.StoreFile("file2", v)
	mg_str, _ := a.ShareFile("file1", "bob")
	mg_str2, _ := a.ShareFile("file2", "bob")

	err := b.ReceiveFile("file2", "alice", mg_str)
	if err == nil {
		t.Error("Used incorrect magic string")
		return
	}

	err = b.ReceiveFile("file1", "alice", mg_str2)
	if err == nil {
		t.Error("Used incorrect magic string")
		return
	}
}

func TestRandomLengthChange(t *testing.T) {
	clear()
	datastore_map := DatastoreGetMap()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "penis")
	v := []byte("This is a test")
	a.StoreFile("file1", v)
	b.StoreFile("file2", v)
	mg_str, _ := a.ShareFile("file1", "bob")
	b.ReceiveFile("file1", "alice", mg_str)

	for key, value := range datastore_map {
		datastore_map[key] = RandomBytes(len(value) + 25)
	}

	_, err := a.LoadFile("file1")
	if err == nil {
		t.Error("Loaded corrupted file with different length")
		return
	}

	err = a.AppendFile("file1", []byte("un-addable changes"))
	if err == nil {
		t.Error("Appended to corrupted file")
		return
	}

	err = a.RevokeFile("file1", "bob")
	if err == nil {
		t.Error("Revoked corrupted file")
		return
	}

	_, err = b.ShareFile("file2", "alice")
	if err == nil {
		t.Error("Shared corrupted file")
		return
	}

	_, err = GetUser("alice", "fubar")
	if err == nil {
		t.Error("able to get corrupted user")
		return
	}
}

func TestSameUsername(t *testing.T) {
	clear()
	InitUser("alice", "fubar")
	_, err := InitUser("alice", "nibbar")
	if err == nil {
		t.Error("Initialized user with same name as another user")
		return
	}
}

func TestDifferentLengthMagicStrings(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "penis")
	v := []byte("This is a test")
	a.StoreFile("file1", v)

	mg_str, _ := a.ShareFile("file1", "bob")
	// empty magic string
	err := b.ReceiveFile("file2", "alice", "")
	if err == nil {
		t.Error("empty magic string")
		return
	}

	err = b.ReceiveFile("file2", "alice", mg_str + "a")
	if err == nil {
		t.Error("wrong length magic string works")
		return
	}
}

func TestReceiveNonexistent(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "as;dlkfj")
	v := []byte("This is gay")
	a.StoreFile("f1", v)
	mg_str, _ := a.ShareFile("f1", "bob")

	// try to receive file from nonexistent user
	err := b.ReceiveFile("haha", "kevin", mg_str)
	if err == nil {
		t.Error("Received file from invalid user")
		return
	}
}
// not testing rollback
/*func TestMixDatastore(t *testing.T) {
	clear()
	datastore_map := DatastoreGetMap()
	a, _ := InitUser("alice", "ieatass69420")
	v := []byte("This is test")
	a.StoreFile("file1", v)
	var prev_map map[uuid.UUID][]byte = make(map[uuid.UUID][]byte)

	for key, _ := range datastore_map {
		prev_map[key] = datastore_map[key]
	}

	a.AppendFile("file1", []byte("append pls"))

	for key, _ := range datastore_map {
		for key2, _ := range prev_map {
			if key == key2 {
				datastore_map[key] = prev_map[key2] // rollback?
			}
		}
	}

	err := a.AppendFile("file1", []byte("another append?"))
	if err == nil {
		t.Error("append shouldn't work?")
		return
	}

	_, err = a.LoadFile("file1")
	if err == nil {
		t.Error("load shouldn't work?")
		return
	}
	// probably shouldn't work, but can't be sure
	_, err = GetUser("alice", "ieatass69420")
	if err == nil {
		t.Error("couldn't load user")
		return
	}
}*/


// func TestMixFiles(t *testing.T) {
// 	clear()
// 	datastore_map := DatastoreGetMap()
// 	a, _ := InitUser("alice", "ieatass69420")
//
// 	var init_map map[uuid.UUID][]byte = make(map[uuid.UUID][]byte)
//
// 	for key, _ := range datastore_map {
// 		init_map[key] = datastore_map[key]
// 	}
//
// 	v := []byte(strings.Repeat("#", 10000))
// 	a.StoreFile("file1", v)
// 	var firstfile_map map[uuid.UUID][]byte = make(map[uuid.UUID][]byte)
//
// 	for key, _ := range datastore_map {
// 		for k, _ := range init_map {
// 			if key != k {
// 				firstfile_map[key] = datastore_map[key]
// 			}
// 		}
// 	}
//
// 	a.StoreFile("file2", v)
// 	var secondfile_map map[uuid.UUID][]byte = make(map[uuid.UUID][]byte)
//
// 	for k, _ := range datastore_map {
// 		for k2, _ := range init_map {
// 			for k3, _ := range firstfile_map {
// 				if (k != k2 && k != k3) {
// 					secondfile_map[k] = datastore_map[k]
// 				}
// 			}
// 		}
// 	}
// 	// may not work depending on implementation
//
// 	for k, v := range firstfile_map {
// 		for k2, v2 := range secondfile_map {
// 			//if (len(v) >= 9000 && len(v2) >= 9000) {
// 				firstfile_map[k] = v2
// 				secondfile_map[k2] = v
// 			//} else if (len(v) < 9000 && len(v) < 9000) {
// 			//	firstfile_map[k] = v2
// 			//	secondfile_map[k2] = v
// 			//}
// 		}
// 	}
//
// 	/*for k, _ := range secondfile_map {
// 		for k2, _ := range datastore_map {
// 			if k == k2 {
// 				datastore_map[k2] = secondfile_map[k]
// 			}
// 		}
// 	}*/
//
// 	var empty_index_arr []int
// 	var uuids []uuid.UUID
// 	var uuids_a []uuid.UUID
//
// 	for k, _ := range secondfile_map {
// 		uuids = append(uuids, k)
// 	}
//
// 	for k, _ := range firstfile_map {
// 		uuids_a = append(uuids_a, k)
// 	}

// 	RecursiveForLoopTwo(t, datastore_map, empty_index_arr, len(uuids), uuids, firstfile_map, a, uuids_a, firstfile_map)
//
// 	/*_, err = a.LoadFile("file2")
// 	if err == nil {
// 		t.Error("load shouldn't work?")
// 		return
// 	}*/
// }


func TestNonRootRevoke(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "foobar")
	v := []byte("This is a test")
	a.StoreFile("file1", v)
	mg_str, _ := a.ShareFile("file1", "bob")

	b.ReceiveFile("file1", "alice", mg_str)

	// b shouldn't be able to revoke
	err := b.RevokeFile("file1", "alice")
	if err == nil {
		t.Error("Non root user revoked file from root user")
		return
	}
}

func TestMixAppend(t *testing.T) {
	clear()
	datastore_map := DatastoreGetMap()
	a, _ := InitUser("alice", "ieatass69420")

	var init_map map[uuid.UUID][]byte = make(map[uuid.UUID][]byte)

	for key, _ := range datastore_map {
		init_map[key] = datastore_map[key]
	}

	v := []byte(strings.Repeat("#", 10000))
	a.StoreFile("file1", v)
	var firstfile_map map[uuid.UUID][]byte = make(map[uuid.UUID][]byte)

	for key, _ := range datastore_map {
		for k, _ := range init_map {
			if key != k {
				firstfile_map[key] = datastore_map[key]
			}
		}
	}

	var append_map map[uuid.UUID][]byte = make(map[uuid.UUID][]byte)
	a.AppendFile("file1", []byte("append"))

	for k, _ := range datastore_map {
		for k2, _ := range init_map {
			for k3, _ := range firstfile_map {
				if (k != k2 && k != k3) {
					append_map[k] = datastore_map[k]
				}
			}
		}
	}

	for k, v := range append_map {
		datastore_map[k] = RandomBytes(len(v))
	}
	// should error, but don't know if it error bc whole file is corrupted
	// or just appended changes are corrupted
	_, err := a.LoadFile("file1")
	if err == nil {
		t.Error("load shouldn't work?")
		return
	}

	/*_, err = a.LoadFile("file2")
	if err == nil {
		t.Error("load shouldn't work?")
		return
	}*/
}

func RecursiveForLoopOne(t *testing.T, datastore_map map[uuid.UUID][]byte, index []int, level int, uuids []uuid.UUID, firstfile_map map[uuid.UUID][]byte, a *User) {
	//var err error
	var err2 error
	var err3 error
	var map_copy map[uuid.UUID][]byte = make(map[uuid.UUID][]byte)

	t.Log(level)
	t.Log(index)
	if level == 0 {
		for key, val := range datastore_map {
			map_copy[key] = val
		}
		for i := 0; i < len(index); i++ {
			datastore_map[uuids[i]] = firstfile_map[uuids[i]]
		}
		//err = a.AppendFile("file1", []byte("try appending"))
		_, err2 = a.LoadFile("file1")
		_, err3 = a.LoadFile("file2")
		/*if err == nil {
			t.Error("append shouldn't work?")
		}*/
		if err2 == nil {
			t.Error("load shouldn't work?")
		}
		if err3 == nil {
			t.Error("load shouldn't work?")
		}
		DatastoreClear()
		for key, val := range map_copy {
			datastore_map[key] = val
		}
	} else {
		for i := 0; i < len(uuids); i++ {
			RecursiveForLoopOne(t, datastore_map, append(index, i), level - 1, uuids, firstfile_map, a)
		}
	}
}

func RecursiveForLoopTwo(t *testing.T, datastore_map map[uuid.UUID][]byte, index []int, level int, uuids []uuid.UUID, secondfile_map map[uuid.UUID][]byte, a *User, uuids_a []uuid.UUID, firstfile_map map[uuid.UUID][]byte) {
	//var err error
	//var err2 error
	var map_copy map[uuid.UUID][]byte = make(map[uuid.UUID][]byte)

	t.Log(level)
	t.Log(index)
	if level == 0 {
		for key, val := range datastore_map {
			map_copy[key] = val
		}
		for i := 0; i < len(index); i++ {
			datastore_map[uuids[i]] = secondfile_map[uuids[i]]
		}

		var ind []int
		RecursiveForLoopOne(t, datastore_map, ind, len(uuids_a), uuids_a, firstfile_map, a)

		DatastoreClear()
		for key, val := range map_copy {
			datastore_map[key] = val
		}
	} else {
		for i := 0; i < len(uuids); i++ {
			RecursiveForLoopTwo(t, datastore_map, append(index, i), level - 1, uuids, secondfile_map, a, uuids_a, firstfile_map)
		}
	}
}
