// Package database — decrypt_stream.go.
//
// Streaming AES-256-GCM decrypter — the inverse of encrypt_stream.go.
// Reads the chunked frame format produced by StreamEncrypter and yields
// plaintext bytes. The wire format is:
//
//	[12 byte nonce][4 byte big-endian ciphertext length][ciphertext]
//	[12 byte nonce][4 byte big-endian ciphertext length][ciphertext]
//	...
//
// where each ciphertext is one AES-256-GCM seal of up to 1 MiB of
// plaintext. The 8-byte big-endian block index is bound to the seal as
// AAD; the decrypter rebuilds the same AAD per block, so any
// reorder/duplicate/drop trips authentication and the read fails closed.
//
// Read() drains the current decrypted block before fetching the next
// frame from the underlying reader, so callers see the same byte-for-byte
// stream the encrypter consumed at write time.
//
// On a clean stream end (zero bytes read while expecting the next nonce)
// Read returns io.EOF. Any short read inside an in-progress frame, any
// length prefix that would imply a ciphertext smaller than the GCM tag
// (i.e. corruption — a real frame is always at least 16 bytes), or any
// failed Open on the AEAD becomes an error: there is no graceful
// recovery for ciphertext corruption.
package database

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// streamMaxFrameSize is a hard ceiling on the per-frame ciphertext length
// we will accept. The encrypter caps plaintext at streamBlockSize (1 MiB)
// plus a 16-byte GCM tag, so any prefix declaring a frame larger than
// this is a sign of either a bug, corruption, or an adversarial input;
// fail closed instead of allocating attacker-controlled buffers.
const streamMaxFrameSize = streamBlockSize + 64

// StreamDecrypter is an io.Reader that consumes the chunked AES-256-GCM
// frame format and yields the original plaintext. NOT safe for
// concurrent use; one decrypter per stream.
type StreamDecrypter struct {
	aead     cipher.AEAD
	in       io.Reader
	blockIdx uint64
	plainBuf []byte // current decoded block, drained by Read calls
	plainPos int    // read offset within plainBuf
	eof      bool   // true once the underlying reader signalled clean EOF
}

// NewStreamDecrypter constructs a streaming AES-256-GCM decrypter over
// in. key must be exactly 32 bytes (AES-256) and must match the key used
// by the encrypter — there is no recovery from a key mismatch, every
// frame's AEAD Open will fail.
func NewStreamDecrypter(key []byte, in io.Reader) (*StreamDecrypter, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("stream: key must be %d bytes (AES-256), got %d", keySize, len(key))
	}
	if in == nil {
		return nil, errors.New("stream: nil reader")
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
	return &StreamDecrypter{
		aead: aead,
		in:   in,
	}, nil
}

// Read implements io.Reader. It drains the current plaintext block; when
// drained, it pulls the next frame from in and decrypts it. Returns
// io.EOF only on a clean frame boundary. Any error encountered while
// reading or authenticating a frame is returned verbatim — the caller
// must treat any non-EOF error as a hard fail (do not continue reading
// after a frame error; subsequent state is undefined).
func (s *StreamDecrypter) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Drain the in-flight plaintext block first.
	if s.plainPos < len(s.plainBuf) {
		n := copy(p, s.plainBuf[s.plainPos:])
		s.plainPos += n
		return n, nil
	}
	if s.eof {
		return 0, io.EOF
	}
	// Need a new frame. Try to read a nonce; clean EOF here is the only
	// place io.EOF is returned to the caller.
	if err := s.nextFrame(); err != nil {
		if errors.Is(err, io.EOF) {
			s.eof = true
			return 0, io.EOF
		}
		return 0, err
	}
	// One byte minimum after a successful frame read; serve it now.
	n := copy(p, s.plainBuf[s.plainPos:])
	s.plainPos += n
	return n, nil
}

// nextFrame reads exactly one nonce + length + ciphertext frame from the
// underlying reader and Opens it into s.plainBuf. On a clean EOF before
// the first nonce byte returns io.EOF; any partial frame is reported as
// io.ErrUnexpectedEOF (or whatever wrapper the underlying reader emits).
func (s *StreamDecrypter) nextFrame() error {
	// Read the 12-byte nonce. We call Read once to detect a clean stream
	// terminator: the encrypter never emits a partial nonce, so
	// io.ReadFull's distinction between "0 bytes + EOF" and "<n bytes +
	// EOF" is the cleanest signal we have.
	var nonce [streamNonceSize]byte
	n, err := io.ReadFull(s.in, nonce[:])
	switch {
	case err == nil:
		// fall through — full nonce read.
	case errors.Is(err, io.EOF) && n == 0:
		// Stream ended on a frame boundary. Clean termination.
		return io.EOF
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("stream: short read on nonce (got %d of %d)", n, streamNonceSize)
	default:
		return fmt.Errorf("stream: read nonce: %w", err)
	}

	// Read the 4-byte big-endian ciphertext length.
	var lenBuf [streamLenPrefixSize]byte
	if _, err := io.ReadFull(s.in, lenBuf[:]); err != nil {
		return fmt.Errorf("stream: read length: %w", err)
	}
	ctLen := binary.BigEndian.Uint32(lenBuf[:])

	// Bounds-check before allocating. A valid frame's ciphertext is at
	// least the GCM tag size (Overhead) — anything smaller cannot be a
	// real frame and is treated as corruption.
	overhead := uint32(s.aead.Overhead())
	if ctLen < overhead {
		return fmt.Errorf("stream: frame %d ciphertext length %d below AEAD overhead %d (corruption)", s.blockIdx, ctLen, overhead)
	}
	if ctLen > streamMaxFrameSize {
		return fmt.Errorf("stream: frame %d ciphertext length %d exceeds maximum %d (corruption or attack)", s.blockIdx, ctLen, streamMaxFrameSize)
	}

	// Read the ciphertext into a fresh buffer. We do not reuse plainBuf
	// for the ciphertext read because Open writes the plaintext length
	// (ctLen - overhead) to its returned slice and we want to keep that
	// allocation for plainBuf below.
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(s.in, ct); err != nil {
		return fmt.Errorf("stream: read ciphertext (frame %d, %d bytes): %w", s.blockIdx, ctLen, err)
	}

	// Build AAD = 8-byte big-endian block index. Mirrors encrypter.
	aad := make([]byte, streamAADSize)
	binary.BigEndian.PutUint64(aad, s.blockIdx)

	// Open authenticates and decrypts. Allocate a destination buffer of
	// the exact plaintext size to avoid reusing a stale, larger buffer
	// that would mask bugs in plainPos accounting.
	plain, err := s.aead.Open(nil, nonce[:], ct, aad)
	if err != nil {
		return fmt.Errorf("stream: authenticate frame %d: %w", s.blockIdx, err)
	}

	s.plainBuf = plain
	s.plainPos = 0
	s.blockIdx++
	return nil
}
