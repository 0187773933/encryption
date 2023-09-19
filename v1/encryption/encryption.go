package encryption

import (
	"os"
	"io"
	filepath "path/filepath"
	base64 "encoding/base64"
	hex "encoding/hex"
	random "crypto/rand"
	bcrypt "golang.org/x/crypto/bcrypt"
	secretbox "golang.org/x/crypto/nacl/secretbox"
	chacha "golang.org/x/crypto/chacha20poly1305"
)

func SecretBoxGenerateRandomKey() ( key [32]byte ) {
	random.Read( key[:] )
	// fmt.Printf( "%x\n" , key )
	return
}

func GenerateRandomString( byte_length int ) ( result string ) {
	b := make( []byte , byte_length )
	random.Read( b )
	result = hex.EncodeToString( b )
	return
}

func SecretBoxGenerateKey( password string ) ( key [32]byte ) {
	password_bytes := []byte( password )
	hashed_password , _ := bcrypt.GenerateFromPassword( password_bytes , ( bcrypt.DefaultCost + 3 ) )
	copy( key[ : ] , hashed_password[ : 32 ] )
	// fmt.Printf( "%x\n" , key )
	return
}

func SecretBoxEncrypt( key string , plain_text string ) ( result string ) {
	key_hex , _ := hex.DecodeString( key )
	var key_bytes [32]byte
	copy( key_bytes[ : ], key_hex )
	plain_text_bytes := []byte( plain_text )
	var nonce [24]byte
	io.ReadFull( random.Reader , nonce[ : ] )
	encrypted_bytes := secretbox.Seal( nonce[ : ] , plain_text_bytes , &nonce , &key_bytes )
	// encrypted_hex_string := hex.EncodeToString( encrypted_bytes[ : ] )
	result = base64.StdEncoding.EncodeToString( encrypted_bytes )
	return
}

func SecretBoxDecrypt( key string , encrypted string ) ( result string ) {
	key_hex , _ := hex.DecodeString( key )
	var key_bytes [32]byte
	copy( key_bytes[ : ], key_hex )
	encrypted_bytes , _ := base64.StdEncoding.DecodeString( encrypted )
	var nonce [24]byte
	copy( nonce[ : ] , encrypted_bytes[ 0 : 24 ] )
	decrypted , _ := secretbox.Open( nil , encrypted_bytes[ 24 : ] , &nonce , &key_bytes )
	result = string( decrypted )
	return
}

func ChaChaGenerateKey( password string ) ( key [32]byte ) {
	password_bytes := []byte( password )
	hashed_password , _ := bcrypt.GenerateFromPassword( password_bytes , ( bcrypt.DefaultCost + 3 ) )
	copy( key[ : ] , hashed_password[ : 32 ] )
	// fmt.Printf( "%x\n" , key )
	return
}

func ChaChaEncryptString( key string , plain_text string ) ( result string ) {
	key_hex , _ := hex.DecodeString( key )
	var key_bytes [32]byte
	copy( key_bytes[ : ], key_hex )
	plain_text_bytes := []byte( plain_text )
	aead , _ := chacha.New( key_bytes[ : ] )
	nonce := make( []byte , aead.NonceSize() )
	io.ReadFull( random.Reader , nonce[ : ] )
	encrypted_bytes := aead.Seal( nil , nonce , plain_text_bytes , nil )
	encrypted_bytes_with_nonce := append( nonce[:] , encrypted_bytes... )
	result = base64.StdEncoding.EncodeToString( encrypted_bytes_with_nonce )
	return
}

func ChaChaDecryptBase64String( key string , encrypted string ) ( result string ) {
	key_hex , _ := hex.DecodeString( key )
	var key_bytes [32]byte
	copy( key_bytes[ : ], key_hex )
	encrypted_bytes , _ := base64.StdEncoding.DecodeString( encrypted )
	aead , _ := chacha.New( key_bytes[ : ] )
	nonce := make( []byte , aead.NonceSize() )
	copy( nonce[ : ] , encrypted_bytes[ 0 : aead.NonceSize() ] )
	decrypted , _ := aead.Open( nil , nonce , encrypted_bytes[ aead.NonceSize() : ] , nil )
	result = string( decrypted )
	return
}

func ChaChaEncryptBytes( key string , plain_text_bytes []byte ) ( result []byte ) {
	key_hex , _ := hex.DecodeString( key )
	var key_bytes [32]byte
	copy( key_bytes[ : ], key_hex )
	aead , _ := chacha.New( key_bytes[ : ] )
	nonce := make( []byte , aead.NonceSize() )
	io.ReadFull( random.Reader , nonce[ : ] )
	encrypted_bytes := aead.Seal( nil , nonce , plain_text_bytes , nil )
	result = append( nonce[:] , encrypted_bytes... )
	return
}

func ChaChaDecryptBytes( key string , encrypted_bytes []byte ) ( result []byte ) {
	key_hex , _ := hex.DecodeString( key )
	var key_bytes [32]byte
	copy( key_bytes[ : ], key_hex )
	aead , _ := chacha.New( key_bytes[ : ] )
	nonce := make( []byte , aead.NonceSize() )
	copy( nonce[ : ] , encrypted_bytes[ 0 : aead.NonceSize() ] )
	decrypted , _ := aead.Open( nil , nonce , encrypted_bytes[ aead.NonceSize() : ] , nil )
	result = decrypted
	return
}

func ChaChaEncryptFile( key string , file_path string ) ( encrypted_file_path string ) {
	key_hex , _ := hex.DecodeString( key )
	var key_bytes [32]byte
	copy( key_bytes[:] , key_hex )
	aead, _ := chacha.New( key_bytes[:] )

	in_file , err := os.Open( file_path )
	if err != nil { return }
	defer in_file.Close()

	encrypted_file_path = file_path + ".encrypted"
	out_file , err := os.Create( encrypted_file_path )
	if err != nil { return }
	defer out_file.Close()

	nonce := make( []byte , aead.NonceSize() )
	io.ReadFull( random.Reader, nonce[:] )
	_ , err = out_file.Write( nonce )
	if err != nil { return }

	chunk_size := 1024
	buffer := make( []byte , chunk_size )
	for {
		n , err := in_file.Read( buffer )
		if err == io.EOF { break }
		if err != nil { return }
		encrypted_bytes := aead.Seal( nil , nonce , buffer[ :n ] , nil )
		_, err = out_file.Write( encrypted_bytes )
		if err != nil { return }
	}
	return
}

func ChaChaDecryptFile( key string , file_path string ) ( result_file_path string ) {
	key_hex, _ := hex.DecodeString(key)
	var key_bytes [32]byte
	copy( key_bytes[:], key_hex )
	aead, _ := chacha.New( key_bytes[:] )

	in_file , err := os.Open( file_path )
	if err != nil { return }
	defer in_file.Close()

	output_file_path := file_path[ :len( file_path )-len( ".encrypted" ) ]
	original_extension := filepath.Ext( output_file_path )
	result_file_path = output_file_path + ".decrypted" + original_extension
	out_file , err := os.Create( result_file_path )
	if err != nil { return }
	defer out_file.Close()

	nonce := make([]byte, aead.NonceSize())
	_ , err = io.ReadFull( in_file , nonce)
	if err != nil { return }

	chunk_size := 1024
	buffer := make( []byte , ( chunk_size + aead.Overhead() ) )

	for {
		n, err := in_file.Read( buffer )
		if err == io.EOF { break }
		if err != nil { return }
		decrypted_bytes , err := aead.Open( nil , nonce , buffer[ :n ] , nil )
		if err != nil { return }
		_ , err = out_file.Write( decrypted_bytes )
		if err != nil { return }
	}

	return
}