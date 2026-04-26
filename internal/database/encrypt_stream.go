// Package database — encrypt_stream.go.
//
// Streaming AES-256-GCM encrypter used by export_dump. The dump tool
// produces an unbounded byte stream; we cannot Seal() the entire dump
// in one shot (it would hold the whole plaintext in RAM). Instead we
// frame the stream into 1-MiB blocks, each independently sealed with a
// fresh nonce.
//
// Per-block format on disk:
//
//	[12 byte nonce][4 byte big-endian ciphertext length][ciphertext]
//
// The ciphertext length is GCM tag + plaintext length (16 bytes
// overhead). The block index is encoded as 8 big-endian bytes and used
// as Additional Authenticated Data (AAD) on the AEAD seal. This binds
// every block to its position in the stream — an attacker who reorders,
// duplicates, or drops blocks will fail authentication on the affected
// frames during restore. (Without AAD-binding, GCM allows an adversary
// to silently splice valid blocks into a different order.)
//
// Nonce reuse is avoided by drawing a random 12 bytes per block. With
// 96-bit nonces and a fresh AES-256 key per export, the birthday bound
// for collision is ~2^48 blocks (~280 PB at 1 MiB blocks), comfortably
// above any plausible single-export size.
//
// The on-disk framing is custom (not CMS / age / etc.) because it must be
// streamable in both directions (encrypt sequentially, decrypt
// sequentially) without any out-of-band manifest. The restorer reads
// nonce + length + ciphertext + repeat to EOF.
package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// streamBlockSize is the plaintext block size. 1 MiB balances
	// throughput (small per-block syscall overhead) against memory
	// pressure (a single block buffer per stream). It must NOT exceed
	// 2^32 - 1 because the on-disk length field is 32 bits.
	streamBlockSize = 1 << 20

	// streamNonceSize is the AES-GCM standard nonce size in bytes.
	streamNonceSize = 12

	// streamLenPrefixSize is the size of the big-endian uint32 ciphertext
	// length prefix.
	streamLenPrefixSize = 4

	// streamAADSize is the size of the per-block additional-authenticated
	// data: an 8-byte big-endian uint64 block index.
	streamAADSize = 8
)

// StreamEncrypter is an io.WriteCloser that buffers plaintext in 1-MiB
// chunks and emits one AES-256-GCM frame per chunk to the underlying
// writer. The final partial chunk is flushed by Close(); failing to call
// Close means the tail of the plaintext is silently dropped.
type StreamEncrypter struct {
	aead     cipher.AEAD
	out      io.Writer
	blockBuf []byte // plaintext accumulator; len <= streamBlockSize
	blockIdx uint64
	closed   bool
}

// NewStreamEncrypter constructs a streaming AES-256-GCM encrypter over
// out. key must be exactly 32 bytes (AES-256).
func NewStreamEncrypter(key []byte, out io.Writer) (*StreamEncrypter, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("stream: key must be %d bytes (AES-256), got %d", keySize, len(key))
	}
	if out == nil {
		return nil, errors.New("stream: nil writer")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("stream: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("stream: gcm: %w", err)
	}
	if aead.NonceSize() != streamNonceSize {
		return nil, fmt.Errorf("stream: unexpected GCM nonce size %d", aead.NonceSize())
	}
	return &StreamEncrypter{
		aead:     aead,
		out:      out,
		blockBuf: make([]byte, 0, streamBlockSize),
	}, nil
}

// Write buffers p until the internal block buffer reaches streamBlockSize,
// at which point one frame is sealed and written. Returns len(p) on
// success (or any short-write error from the underlying writer).
func (s *StreamEncrypter) Write(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("stream: write on closed encrypter")
	}
	written := 0
	for len(p) > 0 {
		room := streamBlockSize - len(s.blockBuf)
		take := len(p)
		if take > room {
			take = room
		}
		s.blockBuf = append(s.blockBuf, p[:take]...)
		p = p[take:]
		written += take
		if len(s.blockBuf) == streamBlockSize {
			if err := s.flushBlock(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// Close flushes any buffered partial block and marks the encrypter
// closed. Subsequent writes return an error. Close does NOT close the
// underlying writer; the caller owns the chain.
func (s *StreamEncrypter) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if len(s.blockBuf) == 0 {
		// Nothing to flush. A zero-length file is still recoverable: the
		// restorer sees EOF immediately and emits empty plaintext.
		return nil
	}
	return s.flushBlock()
}

// flushBlock seals the contents of blockBuf and writes one framed
// ciphertext to out. blockBuf is reset on success.
func (s *StreamEncrypter) flushBlock() error {
	nonce := make([]byte, streamNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("stream: read nonce: %w", err)
	}
	aad := make([]byte, streamAADSize)
	binary.BigEndian.PutUint64(aad, s.blockIdx)

	// Seal returns dst with nonce-prefixed ciphertext if dst is provided
	// (we pass nil so it allocates a fresh buffer of plaintext+tag).
	ct := s.aead.Seal(nil, nonce, s.blockBuf, aad)

	// We bound ciphertext length by uint32. plaintext is at most 1 MiB
	// + 16-byte tag = 1048592, far below 2^32.
	lenPrefix := make([]byte, streamLenPrefixSize)
	binary.BigEndian.PutUint32(lenPrefix, uint32(len(ct)))

	if _, err := s.out.Write(nonce); err != nil {
		return fmt.Errorf("stream: write nonce: %w", err)
	}
	if _, err := s.out.Write(lenPrefix); err != nil {
		return fmt.Errorf("stream: write length: %w", err)
	}
	if _, err := s.out.Write(ct); err != nil {
		return fmt.Errorf("stream: write ciphertext: %w", err)
	}

	// Reset for next block. Reuse the underlying array; capacity is
	// preserved by setting len to 0.
	s.blockBuf = s.blockBuf[:0]
	s.blockIdx++
	return nil
}
