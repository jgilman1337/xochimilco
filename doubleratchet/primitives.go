// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

// This file implements the external functions required by the Double Ratchet
// specification, listed in section 3.1 and 5.2. The recommended algorithms were
// used. SHA-256 was chosen over SHA-512 to save 32 bytes. Furthermore,
// Curve25519 was favored over Curve448 due to its availability.

/*
2024: The cryptography primitives were switched from AES-256-CBC to XChaCha20-Poly1305
since AES in CBC mode lacks authentication and is vulnerable to certain attacks in
certain circumstances. The library, if WASMed, would also potentially fall victim to
timing attacks since AES in software is not as secure as in hardware with proper AES
instructions on the CPU. XChaCha20-Poly1305 is not only faster than software AES, but
more secure too.
	src: https://isuruka.medium.com/selecting-the-best-aes-block-cipher-mode-aes-gcm-vs-aes-cbc-ee3ebae173c
	src: https://security.stackexchange.com/questions/184305/why-would-i-ever-use-aes-256-cbc-if-aes-256-gcm-is-more-secure
	src: https://helpdesk.privateinternetaccess.com/kb/articles/what-s-the-difference-between-aes-cbc-and-aes-gcm
	src: https://link.springer.com/chapter/10.1007/11894063_16
	src: https://www.rfwireless-world.com/Terminology/Advantages-and-disadvantages-of-AES.html
	src: https://www.zenarmor.com/docs/network-security-tutorials/what-is-advanced-encryption-standard-aes

The original HMAC authentication has been kept for compatibility reasons, though it
is redundant since XChaCha20-Poly1305 has its own authentication (the Poly1305 part).
If this HMAC authentication can be removed somehow, then by all means have at it!
*/

package doubleratchet

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// dhKeyPair generates a new Elliptic Curve Diffie-Hellman key pair based on
// Curve25519, RFC 7748.
//
// The Double Ratchet Algorithm specification names this function GENERATE_DH.
func dhKeyPair() (pubKey, privKey []byte, err error) {
	privKey = make([]byte, curve25519.ScalarSize)
	if _, err = rand.Read(privKey); err != nil {
		return
	}

	pubKey, err = curve25519.X25519(privKey, curve25519.Basepoint)
	return
}

// dh calculates an Elliptic Curve Diffie-Hellman shared secret between a
// private key and another peer's public key based on Curve25519, RFC 7748.
//
// The Double Ratchet Algorithm specification names this function DH.
func dh(privKey, pubKey []byte) (sharedSec []byte, err error) {
	if len(privKey) != curve25519.ScalarSize {
		return nil, fmt.Errorf("private key MUST be of %d bytes", curve25519.ScalarSize)
	} else if len(pubKey) != curve25519.PointSize {
		return nil, fmt.Errorf("public key MUST be of %d bytes", curve25519.PointSize)
	}

	return curve25519.X25519(privKey, pubKey)
}

// chainKdf returns a pair (32-byte chain key, 32-byte message key) as the
// output of applying a KDF keyed by a 32-byte chain key to some constant.
//
// Internally an HMAC with SHA-256 is used to derive the two keys from the
// previous chain key. The used constants are 0x00 and 0x01.
//
// The Double Ratchet Algorithm specification names this function KDF_CK.
func chainKdf(ckIn []byte) (ckOut, msgKey []byte, err error) {
	if len(ckIn) != 32 {
		return nil, nil, fmt.Errorf("input chain key MUST be of 32 bytes")
	}

	for i, k := range []*[]byte{&ckOut, &msgKey} {
		mac := hmac.New(sha256.New, ckIn)
		if _, err = mac.Write([]byte{byte(i)}); err != nil {
			return
		}
		*k = mac.Sum(nil)
	}

	return
}

// rootKdf returns a pair (32-byte root key, 32-byte chain key) as the output of
// applying a KDF keyed by a 32-byte root key to a Diffie-Hellman output.
//
// Internally an HKDF with SHA-256 is used, using dh as the secret, rkIn as the
// salt and 0x02 as the info.
//
// The Double Ratchet Algorithm specification names this function KDF_RK.
func rootKdf(rkIn, dh []byte) (rkOut, ck []byte, err error) {
	if len(rkIn) != 32 {
		return nil, nil, fmt.Errorf("input chain key MUST be of 32 bytes")
	}

	kdf := hkdf.New(sha256.New, dh, rkIn, []byte{0x02})
	for _, k := range []*[]byte{&rkOut, &ck} {
		*k = make([]byte, 32)
		if _, err = io.ReadFull(kdf, *k); err != nil {
			return
		}
	}

	return
}

// encryptParams is a helper function for encrypt and decrypt by deriving the
// encryption key, authentication key and IV from a message key.
//
// Because of those parameter's origin, the message key, they are necessary for
// both encryption and decryption. Internally an HKDF based on SHA-256 is used.
// The field's length are fitted for XChaCha20 and SHA-256. Furthermore, the HKDF's
// info is 0x03.
func encryptParams(msgKey []byte) (encKey, authKey, iv []byte, err error) {
	//return encryptParams_insecure(msgKey)

	//Guard
	if len(msgKey) != 32 {
		err = fmt.Errorf("message key MUST be of 32 bytes")
		return
	}

	//Get byte arrays for the encryption key, auth key, and nonce (iv)
	encKey = make([]byte, 32)
	authKey = make([]byte, 32)
	iv = make([]byte, chacha20.NonceSizeX) //Nonce size in XChaCha20 is bigger than ChaCha20

	kdf := hkdf.New(sha256.New, msgKey, bytes.Repeat([]byte{0x00}, sha256.Size), []byte{0x03})
	for _, k := range []*[]byte{&encKey, &authKey, &iv} {
		if _, err = io.ReadFull(kdf, *k); err != nil {
			return
		}
	}

	return

}

// encrypt returns the AEAD encryption of plaintext with a message key. The
// associated data is authenticated but is not included in the ciphertext.
//
// First, a triple of an encryption key, an authentication key and an IV will be
// generated by the encryptParams function. Based on this parameters, the PKCS#7
// padded plaintext will be encrypted with XChaCha20Poly1305. The
// encryption key and IV from before will be used. Second, the associated data
// will be fed into a SHA-256 HMAC with the authentication key. The XChaCha20
// cipher text will be concatenated with the HMAC's result as the final result.
//
// The Double Ratchet Algorithm specification names this function ENCRYPT.
func encrypt(msgKey, plaintext, associatedData []byte) (ciphertext []byte, err error) {
	//Get encryption params
	encKey, authKey, iv, err := encryptParams(msgKey)
	if err != nil {
		return
	}

	//Initialize the XChaCha20 cipher; pre-padding is not necessary since this is a stream cipher
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return
	}

	//Encrypt the plaintext; the raw ciphertext is returned from Seal()
	xchaCipher := aead.Seal(nil, iv, plaintext, nil)

	//Calculate the MAC bytes and append them as AD
	mac := hmac.New(sha256.New, authKey)
	if _, err = mac.Write(associatedData); err != nil {
		return
	}

	//Digest the cipher bytes (encrypt then MAC)
	ciphertext = mac.Sum(xchaCipher)

	//Done!
	return
}

// decrypt returns the AEAD decryption of ciphertext with a message key.
//
// This function does the same as encrypt, just in reverse. Due to the same
// message key and associated data, the same keys will be generated. Thus, on
// the one hand, the XChaCha20 decryption can be performed. On the other hand, the
// same HMAC will be calculated and compared.
//
// The Double Ratchet Algorithm specification names this function DECRYPT.
func decrypt(msgKey, ciphertext, associatedData []byte) (plaintext []byte, err error) {
	//Get encryption params
	encKey, authKey, iv, err := encryptParams(msgKey)
	if err != nil {
		return
	}

	//--Sanity checks start
	if len(ciphertext)-sha256.Size < 0 {
		return nil, fmt.Errorf("ciphertext is too short")
	}

	//Get the raw ciphertext; checks for padding have been omitted since XChaCha20 doesn't use padding since it's a stream cipher
	xchaCipher := ciphertext[:len(ciphertext)-sha256.Size]
	//--Sanity checks end

	//Initialize the XChaCha20 cipher
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return
	}

	//Decrypt the plaintext; the raw plaintext is returned from Open()
	//post-decryption un-padding is not necessary since this is a stream cipher
	plaintext, err = aead.Open(nil, iv, xchaCipher, nil)
	if err != nil {
		return
	}

	//Calculate the MAC bytes and append them as AD
	mac := hmac.New(sha256.New, authKey)
	if _, err = mac.Write(associatedData); err != nil {
		return
	}

	//Digest the cipher bytes (encrypt then MAC)
	macExpect := mac.Sum(nil)

	//Ensure the MACs are equal; this will signal a forged message if they are unequal
	if !hmac.Equal(ciphertext[len(xchaCipher):], macExpect) {
		return nil, fmt.Errorf("HMAC differs")
	}

	//Done!
	return
}
