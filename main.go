package main

import (
	"os"
	"io"
	"io/ioutil"
	"fmt"
	hex "encoding/hex"
	encryption "github.com/0187773933/encryption/v1/encryption"
)

func TestSecretBoxKeyGeneration() {
	x := encryption.SecretBoxGenerateRandomKey()
	x_hex := hex.EncodeToString( x[ : ] )
	// x_b64 := base64.StdEncoding.EncodeToString( x )
	fmt.Printf( "%x === %s === %d\n" , x , x_hex , len( x ) )
	y := encryption.SecretBoxGenerateKey( "2432612431332431436c754a424778736e66796a794b466c32356e794f614836" )
	y_hex := hex.EncodeToString( y[ : ] )
	// y_b64 := base64.StdEncoding.EncodeToString( y )
	fmt.Printf( "%x === %s === %d\n" , y , y_hex , len( y ) )
}

func TestSecretBoxEncryptAndDecrypt() {
	key_test := encryption.GenerateRandomString( 32 )
	encrypted_test := encryption.SecretBoxEncrypt( key_test , "Lorem ipsum dolor sit amet, consectetuer adipiscing elit." )
	fmt.Println( encrypted_test )
	fmt.Println( encryption.SecretBoxDecrypt( key_test , encrypted_test ) )
}

func TestChaChaEncryptDecrypt() {
	key_test := encryption.GenerateRandomString( 32 )
	x := encryption.ChaChaEncryptString( key_test , "asdf" )
	y := encryption.ChaChaDecryptBase64String( key_test , x )
	fmt.Printf( "%+v\n" , x )
	fmt.Println( y )
}

func TestChaChaEncryptDecryptFile() {
	// 1.) Create random text file
	temp_file , _ := os.CreateTemp( "" , "test-" )
	temp_file_path := temp_file.Name()
	fmt.Println( temp_file_path )
	io.WriteString( temp_file , "Lorem ipsum dolor sit amet, consectetuer adipiscing elit." );
	un_encrypted , _ := ioutil.ReadFile( temp_file_path )
	fmt.Println( string( un_encrypted ) )

	// 2.) Encrypt it
	key_test := encryption.GenerateRandomString( 32 )
	encrypted_file_path := encryption.ChaChaEncryptFile( key_test , temp_file_path )
	encrypted , _ := ioutil.ReadFile( encrypted_file_path )
	fmt.Println( string( encrypted ) )

	// 3.) Decrypt It
	de_crypted_file_path := encryption.ChaChaDecryptFile( key_test , encrypted_file_path )
	decrypted , _ := ioutil.ReadFile( de_crypted_file_path )
	fmt.Println( string( decrypted ) )

	os.Remove( temp_file_path )
	os.Remove( encrypted_file_path )
	os.Remove( de_crypted_file_path )
}

func TestCurve25519() {

	// 1.) Setup Keys For Both Parties
	// Sender
	alice_public_key , alice_private_key := encryption.CurveX25519GenerateKeyPair()
	fmt.Println( alice_public_key , alice_private_key )

	// Receiver
	bob_public_key , bob_private_key := encryption.CurveX25519GenerateKeyPair()
	fmt.Println( bob_public_key , bob_private_key )

	// 2.) Whenever Alice wants to "establish a session" :
	// 2.1) alice needs to obtain bob's public key somehow.
	// its usually sent over some plain-text method to alice
		// bob_public_key := http.Get( "/users/bob/public-key" )
	// we already have it here conveniently in our test example
	// 2.2) Alice computes a shared secret for the "session" to use.
	alices_shared_secret_for_session := encryption.CurveX25519KeyExchange( alice_private_key , bob_public_key )

	// 3.) Sender Encrypts the Message
	plain_text_message := "asdf"
	plain_text_message_bytes := []byte( plain_text_message )
	encrypted_message := encryption.ChaChaSharedSecretEncryptMessage( alices_shared_secret_for_session , plain_text_message_bytes )
	fmt.Println( encrypted_message )

	// 4.) Whenever Bob Wants to Decrypte a message
	// 4.1) Have to obtain public key of the sender
		// alice_public_key := http.Get( "/users/alice/public-key" )
	// 4.2) Compute the same shared secret that exists between the two parties
	bobs_shared_secret_for_session := encryption.CurveX25519KeyExchange( bob_private_key , alice_public_key )
	// bobs_shared_secret_for_session and alices_shared_secret_for_session should be the same , and never change for any 2 sets of keypairs
	// step 2 and 4 happen essentially at the same exact time

	// 5.) Reciever Decrypts the message
	decrypted_message := encryption.ChaChaSharedSecretDecryptMessage( bobs_shared_secret_for_session , encrypted_message )
	fmt.Println( string( decrypted_message ) )

}

func TestKyber() {

	// 1.) Setup Keys For Both Parties
	// 1.1) Sender-Normal
	alice_public_key , alice_private_key := encryption.CurveX25519GenerateKeyPair()
	fmt.Println( alice_public_key , alice_private_key )
	// 1.2) Sender-Quantum
	alice_public_key_q , alice_private_key_q := encryption.KyberGenerateKeyPair()
	fmt.Println( alice_public_key_q , alice_private_key_q )

	// 1.3) Receiver-Normal
	bob_public_key , bob_private_key := encryption.CurveX25519GenerateKeyPair()
	fmt.Println( bob_public_key , bob_private_key )
	// 1.4) Receiver-Quantum
	bob_public_key_q , bob_private_key_q := encryption.KyberGenerateKeyPair()
	fmt.Println( bob_public_key_q , bob_private_key_q )

	// 2.) Whenever Alice wants to "establish a session" :
	// 2.1) alice needs to obtain bob's public key somehow.
	// its usually sent over some plain-text method to alice
		// bob_public_key_q := http.Get( "/users/bob/public-key-q" )
	// we already have it here conveniently in our test example
	// 2.2) Alice computes a shared secret for the "session" to use.
	// alices_shared_secret_for_session := encryption.CurveX25519KeyExchange( alice_private_key , bob_public_key )
	// 2.2-kyber-style) Alice computes a "cipher-text" and a shared secret
	cipher_text_to_bob , alices_shared_secret_for_session := encryption.KyberEncrypt( bob_public_key_q )

	// 3.) this is a new independent step , different than how normal key exchange works
	// in kyber , both parties can't just generate a shared key
	// we have to transmit this cipher_text_to_bob to bob
	// then bob can use this to derive the shared secret key
	// from bob's computer -> http.Get( "/users/alice/to/bob/cipher-text" , cipher_text_to_bob )

	// 4.) Sender Encrypts the Message
	plain_text_message := "asdf"
	plain_text_message_bytes := []byte( plain_text_message )
	encrypted_message := encryption.ChaChaSharedSecretEncryptMessage( alices_shared_secret_for_session , plain_text_message_bytes )
	fmt.Println( encrypted_message )

	// 5.) Whenever Bob Wants to Decrypte a message
	// 5.1) Have to obtain public key of the sender , AND now the cipher text
		// alice_public_key := http.Get( "/users/alice/public-key" )
		// cipher_text_to_bob := http.Get( "/users/alice/to/bob/cipher-text" , cipher_text_to_bob )
	// 5.2) Compute the same shared secret that exists between the two parties
	bobs_shared_secret_for_session := encryption.KyberDecrypt( cipher_text_to_bob , bob_private_key_q )
	// bobs_shared_secret_for_session and alices_shared_secret_for_session should be the same , and never change for any 2 sets of keypairs
	// step 2 and 5 happen essentially at the same exact time

	// 6.) Reciever Decrypts the message
	decrypted_message := encryption.ChaChaSharedSecretDecryptMessage( bobs_shared_secret_for_session , encrypted_message )
	fmt.Println( string( decrypted_message ) )

}

func main() {
	// TestSecretBoxKeyGeneration()
	// TestSecretBoxEncryptAndDecrypt()
	// TestChaChaEncryptDecrypt()
	// TestChaChaEncryptDecryptFile()
	// TestCurve25519()
	TestKyber()
}