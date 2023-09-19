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

func main() {
	// TestSecretBoxKeyGeneration()
	// TestSecretBoxEncryptAndDecrypt()
	// TestChaChaEncryptDecrypt()
	TestChaChaEncryptDecryptFile()
}