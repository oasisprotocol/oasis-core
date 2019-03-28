// Package sivaessha2 implements the SIV_CTR-AES128_HMAC-SHA256-128
// algorithm.
package sivaessha2

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"

	aes "git.schwanenlied.me/yawning/bsaes.git"

	"github.com/oasislabs/ekiden/go/common/crypto/mrae/api"
)

const (
	// KeySize is the size of the expanded SIV_CTR-AES128_HMAC-SHA256-128
	// key in bytes.
	KeySize = 48

	// NonceSize is the recommended size of the nonce in bytes.
	NonceSize = 16

	// TagSize is the size of the authentication tag in bytes.
	TagSize = 16
)

var (
	// ErrInvalidKeySize is the error returned when the key size is
	// invalid.
	ErrInvalidKeySize = errors.New("sivaessha2: invalid key size")

	// ErrInvalidAADSize is the error returned (or thrown via panic),
	// when the additional data is under/oversized.
	ErrInvalidAADSize = errors.New("sivaessha2: invalid AAD size")

	// ErrInvalidPlaintextSize is the error returned (or thrown via panic),
	// when the plaintext is under/oversized.
	ErrInvalidPlaintextSize = errors.New("sivaessha2: invalid plaintext size")

	// ErrAuthFailed is the error returned when the message authentication
	// has failed.
	ErrAuthFailed = errors.New("sivaessha2: message authentication failed")

	_ cipher.AEAD = (*sivImpl)(nil)
)

type sivImpl struct {
	macKey []byte
	ctrKey []byte
}

// NonceSize returns the size of the nonce that SHOULD be passed to
// Seal and Open.
func (s *sivImpl) NonceSize() int {
	return NonceSize
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (s *sivImpl) Overhead() int {
	return TagSize
}

// Seal encrypts and auntenticates plaintext, authenticates the additional
// data and appends the result to dst, returning the updated slice.  The
// nonce SHOULD be NonceSize() bytes long and unique for all time, for
// a given key.
//
// The plaintext and dst must overlap exactly or not at all.  To reuse
// plaintext's storage for encrypted output, use plaintext[:0] as dst.
//
// Note: Nonces of arbitrary lengths will be accepted.
func (s *sivImpl) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	aadLen, pLen := len(additionalData), len(plaintext)

	mac := hmac.New(sha256.New, s.macKey)
	_, _ = mac.Write(nonce)
	if err := writeLenVec(mac, aadLen, pLen); err != nil {
		panic(err)
	}
	_, _ = mac.Write(additionalData)
	_, _ = mac.Write(plaintext)
	siv := mac.Sum(nil)[:TagSize]

	ret, out := sliceForAppend(dst, pLen+TagSize)

	blk, err := aes.NewCipher(s.ctrKey)
	if err != nil {
		panic(err)
	}
	ctr := cipher.NewCTR(blk, siv)
	ctr.XORKeyStream(out, plaintext)
	copy(out[pLen:], siv)

	return ret
}

// Open decrypts and authenticates ciphertext, authenticates the additional
// data and, if successful, appends the resulting plaintext to dst,
// returning the updated slice.  The nonce SHOULD be NonceSize() bytes long
// and both it and the additional data must match the value passed to Seal.
//
// The ciphertext and dst must overlap exactly or not at all.  To reuse
// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst.
//
// Even if the function fails, the contents of dst, up to it's capacity,
// may be overwritten.
func (s *sivImpl) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	aadLen, pLen := len(additionalData), len(ciphertext)-TagSize

	// Start MACing first.
	mac := hmac.New(sha256.New, s.macKey)
	_, _ = mac.Write(nonce)
	if err := writeLenVec(mac, aadLen, pLen); err != nil {
		return nil, err
	}
	_, _ = mac.Write(additionalData)

	var siv []byte
	ciphertext, siv = ciphertext[:pLen], ciphertext[pLen:]
	ret, out := sliceForAppend(dst, pLen)

	blk, err := aes.NewCipher(s.ctrKey)
	if err != nil {
		panic(err)
	}
	ctr := cipher.NewCTR(blk, siv)
	ctr.XORKeyStream(out, ciphertext)

	_, _ = mac.Write(out)

	sivCmp := mac.Sum(nil)[:TagSize]
	if !hmac.Equal(siv, sivCmp) {
		for i := range out {
			out[i] = 0
		}
		return nil, ErrAuthFailed
	}

	return ret, nil
}

func (s *sivImpl) Reset() {
	api.Bzero(s.macKey)
	api.Bzero(s.ctrKey)
}

// New creates a new cipher.AEAD instance using SIV_CTR-AES128_HMAC-SHA256-128
// with the provided key.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	return &sivImpl{
		macKey: append([]byte{}, key[:32]...),
		ctrKey: append([]byte{}, key[32:]...),
	}, nil
}

func writeLenVec(w io.Writer, aadLen, pLen int) error {
	if int64(aadLen) > math.MaxUint32 /* || aadLen < 0 */ {
		return ErrInvalidAADSize
	}
	if int64(pLen) > math.MaxUint32 || pLen < 0 {
		return ErrInvalidPlaintextSize
	}

	var tmp [8]byte
	binary.BigEndian.PutUint32(tmp[0:4], uint32(aadLen))
	binary.BigEndian.PutUint32(tmp[4:8], uint32(pLen))
	_, err := w.Write(tmp[:])
	return err
}

// Shamelessly stolen from the Go runtime library.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
