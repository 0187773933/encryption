package encryption

import (
	"fmt"
	"os"
	"io"
	"time"
	sha256 "crypto/sha256"
	binary "encoding/binary"
	filepath "path/filepath"
	base64 "encoding/base64"
	hex "encoding/hex"
	random "crypto/rand"
	bcrypt "golang.org/x/crypto/bcrypt"
	secretbox "golang.org/x/crypto/nacl/secretbox"
	chacha "golang.org/x/crypto/chacha20poly1305"
	curve25519 "golang.org/x/crypto/curve25519"
	// ed25519 "crypto/ed25519"
	kyberk2so "github.com/symbolicsoft/kyber-k2so"
)

func GenerateEntropyBytes1( byte_length int ) ( result []byte ) {
	b := make( []byte , byte_length )
	random.Read( b )
	result = b
	return
}

func GenerateEntropyBytes2( byte_length int ) ( result []byte ) {
	now := time.Now().UnixNano()
	buf := make( []byte , byte_length )
	binary.LittleEndian.PutUint64( buf , uint64( now ) )
	result = buf
	return
}

func Sha256Sum( entries [][]byte  ) ( result []byte ) {
	hasher := sha256.New()
	for _ , entry := range entries {
		hasher.Write( entry )
	}
	result = hasher.Sum( nil )
	return
}

func GenerateRandomBytes( byte_length int ) ( result []byte ) {
	counter := 0
	for len( result ) < byte_length {
		entropy_one := GenerateEntropyBytes1( byte_length )
		entropy_two := GenerateEntropyBytes2( byte_length )
		counter_bytes := make( []byte , byte_length )
		binary.LittleEndian.PutUint64( counter_bytes , uint64( counter ) )
		counter++
		block := Sha256Sum( [][]byte{ entropy_one , entropy_two , counter_bytes } )
		result = append( result , block... )
	}
	result = result[ : byte_length ]
	return
}

func GenerateRandomString( byte_length int ) ( result string ) {
	b := GenerateRandomBytes( byte_length )
	result = hex.EncodeToString( b )
	return
}

func SecretBoxGenerateRandomKey() ( key [32]byte ) {
	x := GenerateRandomBytes( 32 )
	copy( key[ : ] , x )
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

func CurveX25519GenerateKeyPair() ( public_key [32]byte , private_key [32]byte ) {
	_ , err := random.Read( private_key[:] )
	if err != nil { fmt.Println( err ); return }
	var public_key_bytes []byte
	public_key_bytes , err = curve25519.X25519( private_key[:] , curve25519.Basepoint )
	if err != nil { fmt.Println( err ); return }
	copy( public_key[:] , public_key_bytes )
	return
}

// X25519KeyExchange performs a key exchange to compute a shared secret given
// a private key and another party's public key.
func CurveX25519KeyExchange( private_key [32]byte , other_public_key [32]byte ) ( shared_secret [32]byte ) {
	shared_secret_bytes , err := curve25519.X25519( private_key[:] , other_public_key[:] )
	if err != nil { fmt.Println( err ); return }
	copy( shared_secret[:] , shared_secret_bytes )
	return
}

func ChaChaSharedSecretEncryptMessage( shared_secret [32]byte , message []byte ) ( encrypted_message []byte ) {
	// Initialize the cipher with the shared secret
	cipher , err := chacha.NewX( shared_secret[:] )
	if err != nil { fmt.Errorf( "failed to create cipher: %w" , err ); return }

	// Generate a nonce for this encryption. Nonce needs to be unique for each encryption to ensure security.
	nonce := make( []byte , chacha.NonceSizeX )
	io.ReadFull( random.Reader , nonce[ : ] )

	// Encrypt the message using the cipher
	// Prepend the nonce to the encrypted message
	encrypted_message = cipher.Seal( nonce , nonce , message , nil )
	return
}

func ChaChaSharedSecretDecryptMessage( shared_secret [32]byte , encrypted_message []byte ) ( plain_text []byte ) {
	// Initialize the cipher with the shared secret
	cipher , err := chacha.NewX( shared_secret[:] )
	if err != nil { fmt.Errorf( "failed to create cipher: %w" , err ); return }

	// The nonce is the first part of the encrypted message
	nonce := encrypted_message[ : chacha.NonceSizeX ]
	encrypted := encrypted_message[ chacha.NonceSizeX : ]

	// Decrypt the message using the cipher
	decrypted , err := cipher.Open( nil , nonce , encrypted , nil )
	if err != nil { fmt.Errorf( "failed to decrypted: %w" , err ); return }
	plain_text = decrypted

	return
}

// 1024 bit keypair
// lattice space = determined by keypair vectors. public
// public key = "bad" basis vector = far from perpendicular , long
// private key = "good" basis vector = close to perpendicular , short
	// - allows the receiver correct the errors of the ciphertext
		// - finding nearest neighbor efficiently
			// - navigate the lattice and perform a form of error correction ( de-noise )
// cipher text :
	// - essentially its a "noisy" shared key
	// - its some point in the lattice space that is in-between the real members of the lattice.
	// - its "noisy" , translated away from a true valid point.
	// - the attacker can't tell from which of the original points it was derived from
// https://cryptopedia.dev/posts/kyber
// https://www.youtube.com/watch?v=QDdOoYdb748
// https://www.youtube.com/watch?v=K026C5YaB3A
// https://en.wikipedia.org/wiki/Grover's_algorithm
func KyberGenerateKeyPair() ( public_key [1568]byte , private_key [3168]byte ) {
	private_key , public_key , _ = kyberk2so.KemKeypair1024()
	return
}

func KyberEncrypt( public_key [1568]byte ) ( cipher_text [1568]byte , shared_secret [32]byte ) {
	cipher_text , shared_secret , _ = kyberk2so.KemEncrypt1024( public_key )
	return
}

func KyberDecrypt( cipher_text [1568]byte , private_key [3168]byte ) ( shared_secret [32]byte ) {
	shared_secret , _ = kyberk2so.KemDecrypt1024( cipher_text , private_key )
	return
}