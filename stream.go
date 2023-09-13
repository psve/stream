// Package stream implements "online authenticated encryption" using the STREAM
// construction from "Online Authenticated-Encryption and its Nonce-Reuse
// Misuse-Resistance", see https://eprint.iacr.org/2015/189.pdf.
//
// STREAM splits the ciphertext into chunks and processes each chunk using a traditional
// AEAD. Part of the AEAD's nonce is reserved for a header which holds a counter and a
// sentinel byte for the last chunk.
//
// For this instantiation of STREAM, the header is 4 bytes long. Byte 0 of the nonce
// holds the sentinel value: it is 1 for the last chunk and 0 for all others. Bytes 1-3
// of the nonce holds the 24 bit counter value. The remaining bytes of the nonce are
// randomly generated. The chunk size is 64 KiB.
//
// The additional data is only passed to the first chunk for simplicity. The final chunk
// can be less than the chunk size. The ciphertext chunks are then:
//
//	0:   0 || counter(0) || nonce || AEAD(plaintext_0, 0 || counter(0) || nonce, additional_data)
//	1:   0 || counter(1) || nonce || AEAD(plaintext_1, 0 || counter(1) || nonce, nil)
//	2:   0 || counter(2) || nonce || AEAD(plaintext_2, 0 || counter(2) || nonce, nil)
//	...
//	n-1: 0 || counter(n-1) || nonce || AEAD(plaintext_n-1, 0 || counter(n-1) || nonce, nil)
//	n:   1 || counter(n)   || nonce || AEAD(plaintext_n  , 1 || counter(n)   || nonce, nil)
//
// Note that the order of the chunks is checked during decryption.
package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	// ChunkSize is the size of each plaintext chunk.
	ChunkSize = 64 * 1024

	// counterOverhead is the number of bytes of the nonce used for the counter/header.
	counterOverhead = 4
)

var ErrModifiedStream = errors.New("modified stream")
var ErrTruncatedStream = errors.New("truncated stream")
var ErrWriteAfterClose = errors.New("write after close")

type data struct {
	chunk []byte
	nonce []byte
}

// STREAM is a cipher mode providing "online authenticated encryption" also known as
// chunked or streaming authenticated encryption. It provides two ways of doing
// streaming encryption:
//   - Seal/Open functionality similar to the crypto/cipher.AEAD interface, but using
//     io.Reader/io.Writer for input/output.
//   - Wrappers around io.Reader/io.Writer.
type STREAM struct {
	// aead is the underlying AEAD construction.
	aead cipher.AEAD

	// This pools help amortize buffer allocations when the same STREAM instance is used
	// multiple times.
	dataPool *sync.Pool
}

// NewSTREAM creates a new STREAM instance which uses the provided AEAD internally to
// encrypt/decrypt each chunk. The maximum number of bytes that can safely be processed
// is 1 TiB.
//
// Note that since STREAM reserves part of the AEAD's nonce for a counter/header, one
// should be careful about encrypting a large number of streams under the same key when
// using an AEAD with a relatively small nonce.
func NewSTREAM(aead cipher.AEAD) *STREAM {
	return &STREAM{
		aead: aead,
		dataPool: &sync.Pool{New: func() any {
			r := &data{
				chunk: make([]byte, ChunkSize+aead.Overhead()),
				nonce: make([]byte, aead.NonceSize()),
			}
			return r
		}},
	}
}

// Seal encrypts and authenticates plaintext, authenticates the additional data and
// writes the result to dst in chunks of size ChunkSize + ChunkOverhead().
func (s *STREAM) Seal(dst io.Writer, plaintext io.Reader, additionalData []byte) error {
	sw, err := s.NewWriter(dst, additionalData)
	if err != nil {
		return err
	}
	if _, err := sw.ReadFrom(plaintext); err != nil {
		return fmt.Errorf("could not write ciphertext: %w", err)
	}
	return nil
}

// Open decrypts and authenticates ciphertext, authenticates the additional data and
// writes the resulting plaintext to dst. The additional data must match the value
// passed to Seal.
//
// If an error is returned, the data written to dst should not be trusted.
func (s *STREAM) Open(dst io.Writer, ciphertext io.Reader, additionalData []byte) error {
	sr := s.NewReader(ciphertext, additionalData)
	if _, err := sr.WriteTo(dst); err != nil {
		return fmt.Errorf("could not read plaintext: %w", err)
	}
	return nil
}

// Overhead returns the maximum difference between the lengths of a single plaintext
// chunk and the corresponding ciphertext chunk.
func (s *STREAM) ChunkOverhead() int {
	return s.aead.NonceSize() + s.aead.Overhead()
}

// Overhead returns the maximum difference between the lengths of a plaintext and its
// ciphertext.
func (s *STREAM) Overhead(bytes int) int {
	if bytes == 0 {
		return s.ChunkOverhead()
	}
	chunks := bytes / ChunkSize
	if (bytes % ChunkSize) != 0 {
		chunks++
	}
	return chunks * s.ChunkOverhead()
}

// STREAMWriter is a wrapper which will encrypt data to an underlying io.Writer.
// It implements io.WriteCloser and io.ReaderFrom.
type STREAMWriter struct {
	w        io.Writer
	aead     cipher.AEAD
	dataPool *sync.Pool
	d        *data
	ad       []byte
	closed   bool
}

// NewWriter returns a new STREAMWriter which wraps w.
func (s *STREAM) NewWriter(w io.Writer, additionalData []byte) (*STREAMWriter, error) {
	sw := &STREAMWriter{
		w:        w,
		aead:     s.aead,
		dataPool: s.dataPool,
		d:        (s.dataPool.Get().(*data)),
		ad:       additionalData,
	}
	sw.d.chunk = sw.d.chunk[:0]
	if _, err := rand.Read(sw.d.nonce[counterOverhead:]); err != nil {
		return nil, fmt.Errorf("could not generate nonce: %w", err)
	}
	return sw, nil
}

// Write will encrypt p and write the result to the underlying io.Writer. Once all data
// has been written, the caller must call Close to make sure that all data is flushed to
// the underlying Writer. Note that Close can error even when all Write calls succeeded.
// Callers should always check the error from Close.
func (sw *STREAMWriter) Write(p []byte) (int, error) {
	if sw.closed {
		return 0, ErrWriteAfterClose
	}

	for idx := 0; idx < len(p); {
		switch {
		case len(sw.d.chunk) == 0 && len(p[idx:]) >= ChunkSize:
			// If there's nothing in our buffer, and we could buffer an entire chunk, just use
			// p as input directly.
			if _, err := sw.w.Write(sw.d.nonce); err != nil {
				return idx, fmt.Errorf("could not write nonce: %w", err)
			}
			if _, err := sw.w.Write(sw.aead.Seal(sw.d.chunk[:0], sw.d.nonce, p[idx:idx+ChunkSize], sw.ad)); err != nil {
				return idx, fmt.Errorf("could not write chunk: %w", err)
			}

			sw.ad, sw.d.chunk = nil, sw.d.chunk[:0]
			sw.increaseCounter()
			idx += ChunkSize
		case len(sw.d.chunk) < ChunkSize:
			// If we don't have a full chunk buffer yet, buffer as much as possible. Note that
			// the buffer always has capacity ChunkSize, so this doesn't allocate.
			canBuffer := min(len(p)-idx, ChunkSize-len(sw.d.chunk))
			sw.d.chunk = append(sw.d.chunk, p[idx:idx+canBuffer]...)
			idx += canBuffer
		case len(sw.d.chunk) == ChunkSize:
			// We have filled up our plaintext buffer, write the next chunk.
			if _, err := sw.w.Write(sw.d.nonce); err != nil {
				return idx, fmt.Errorf("could not write nonce: %w", err)
			}
			if _, err := sw.w.Write(sw.aead.Seal(sw.d.chunk[:0], sw.d.nonce, sw.d.chunk, sw.ad)); err != nil {
				return idx, fmt.Errorf("could not write chunk: %w", err)
			}

			sw.ad, sw.d.chunk = nil, sw.d.chunk[:0]
			sw.increaseCounter()
			idx += ChunkSize
		}
	}

	return len(p), nil
}

// Close flushes all data to the underlying io.Writer and closes the stream. Subsequent
// calls to Close is a no-op.
func (sw *STREAMWriter) Close() error {
	if sw.closed {
		return nil
	}

	// Indicate that this is the last chunk and write it.
	sw.d.nonce[0] = 1
	if _, err := sw.w.Write(sw.d.nonce); err != nil {
		return fmt.Errorf("could not write nonce: %w", err)
	}
	if _, err := sw.w.Write(sw.aead.Seal(sw.d.chunk[:0], sw.d.nonce, sw.d.chunk, sw.ad)); err != nil {
		return fmt.Errorf("could not write chunk: %w", err)
	}

	clear(sw.d.nonce[:counterOverhead])
	sw.dataPool.Put(sw.d)
	sw.ad = nil
	sw.closed = true
	return nil
}

// ReadFrom will consume all data from r and write the encrypted result to the
// underlying io.Writer.
func (sw *STREAMWriter) ReadFrom(r io.Reader) (int64, error) {
	if sw.closed {
		return 0, ErrWriteAfterClose
	}

	read := int64(0)
	for ; sw.d.nonce[0] != 1; sw.increaseCounter() {
		n, err := io.ReadFull(r, sw.d.chunk[:ChunkSize])
		read += int64(n)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// This is the last chunk
			sw.d.nonce[0] = 1
		} else if err != nil {
			return read, fmt.Errorf("could not read chunk: %w", err)
		}
		if _, err := sw.w.Write(sw.d.nonce); err != nil {
			return read, fmt.Errorf("could not write nonce: %w", err)
		}
		if _, err := sw.w.Write(sw.aead.Seal(sw.d.chunk[:0], sw.d.nonce, sw.d.chunk[:n], sw.ad)); err != nil {
			return read, fmt.Errorf("could not write chunk: %w", err)
		}
		sw.ad = nil
	}

	clear(sw.d.nonce[:counterOverhead])
	sw.dataPool.Put(sw.d)
	sw.closed = true
	return read, nil
}

// increaseCounter increments the counter part of the header.
func (sw *STREAMWriter) increaseCounter() {
	if sw.d.nonce[1]++; sw.d.nonce[1] != 0 {
		return
	}
	if sw.d.nonce[2]++; sw.d.nonce[2] != 0 {
		return
	}
	sw.d.nonce[3]++
}

// STREAMReader is a wrapper which will decrypt data from an underlying io.Reader. It
// implements io.ReadCloser and io.WriterTo.
type STREAMReader struct {
	r          io.Reader
	aead       cipher.AEAD
	dataPool   *sync.Pool
	d          *data
	chunkIdx   int
	chunkCount int
	ad         []byte
	closed     bool
}

// NewReader returns a new STREAMReader which wraps r.
func (s *STREAM) NewReader(r io.Reader, additionalData []byte) *STREAMReader {
	sr := &STREAMReader{
		r:        r,
		aead:     s.aead,
		dataPool: s.dataPool,
		d:        (s.dataPool.Get().(*data)),
		chunkIdx: ChunkSize,
		ad:       additionalData,
	}
	sr.d.chunk = sr.d.chunk[:cap(sr.d.chunk)]
	return sr
}

// Read will decrypt data from the underlying io.Reader and write the result to p. Once
// all data has been read, the caller must call Close.
func (sr *STREAMReader) Read(p []byte) (int, error) {
	if sr.closed {
		return 0, io.EOF
	}

	out, inplace := sr.d.chunk, false

	for idx := 0; idx < len(p); {
		switch {
		case sr.d.nonce[0] == 1 && sr.chunkIdx == len(out):
			// We have read the last chunk and used the entire plaintext buffer. There's
			// nothing left to do.
			return idx, io.EOF
		case inplace && sr.chunkIdx < ChunkSize:
			// We just did an inplace operation, just update the indices.
			idx += len(out)
			sr.chunkIdx += len(out)
		case sr.chunkIdx < ChunkSize:
			// We still have plaintext available in the buffer. Copy as many bytes as
			// possible.
			copied := copy(p[idx:], out[sr.chunkIdx:])
			idx += copied
			sr.chunkIdx += copied
		case sr.chunkIdx == ChunkSize:
			// We havn't read the last chunk yet, but we have run out of plaintext buffer. Try
			// to read the next chunk.
			if _, err := io.ReadFull(sr.r, sr.d.nonce); err != nil {
				return idx, fmt.Errorf("could not read nonce: %w", err)
			}
			if sr.chunkCount != sr.getCounter() {
				return idx, ErrModifiedStream
			}

			// If p has enough capacity we can read directly to that instead of staging
			// through the buffer.
			if cap(p[idx:]) >= ChunkSize+sr.aead.Overhead() {
				out, inplace = p[idx:], true
			} else {
				out, inplace = sr.d.chunk, false
				defer func() { sr.d.chunk = out }()
			}

			// Growing the slice here to make room for the ciphertext chunk doesn't require
			// allocation:
			// - sr.d.chunk always has capacity ChunkSize+sr.aead.Overhead().
			// - In case of an inplace operation the check above ensures that p has enough
			//   capacity.
			out = out[:ChunkSize+sr.aead.Overhead()]

			n, err := io.ReadFull(sr.r, out)
			if sr.d.nonce[0] != 1 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
				return idx, ErrTruncatedStream
			}
			out, err = sr.aead.Open(out[:0], sr.d.nonce, out[:n], sr.ad)
			if err != nil {
				return idx, fmt.Errorf("decryption failed: %w", err)
			}

			sr.ad, sr.chunkIdx = nil, 0
			sr.chunkCount++
		}
	}

	return len(p), nil
}

// Close frees underlying resources used by the STREAMReader. Subsequent calls to Close
// is a no-op.
func (sr *STREAMReader) Close() error {
	if sr.closed {
		return nil
	}

	clear(sr.d.nonce[:counterOverhead])
	sr.d.chunk = sr.d.chunk[:cap(sr.d.chunk)]
	sr.dataPool.Put(sr.d)
	sr.ad = nil
	sr.closed = true
	return nil
}

// ReadFrom will consume all data from the underlying io.Reader and write the decrypted
// result to w.
func (sr *STREAMReader) WriteTo(w io.Writer) (int64, error) {
	if sr.closed {
		return 0, io.EOF
	}

	written := int64(0)
	for chunk := 0; sr.d.nonce[0] != 1; chunk++ {
		if _, err := io.ReadFull(sr.r, sr.d.nonce); err != nil {
			return written, fmt.Errorf("could not read nonce: %w", err)
		}
		if chunk != sr.getCounter() {
			return written, ErrModifiedStream
		}
		n, err := io.ReadFull(sr.r, sr.d.chunk)
		if sr.d.nonce[0] != 1 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			return written, ErrTruncatedStream
		}
		out, err := sr.aead.Open(sr.d.chunk[:0], sr.d.nonce, sr.d.chunk[:n], sr.ad)
		if err != nil {
			return written, fmt.Errorf("decryption failed: %w", err)
		}
		n, err = w.Write(out)
		written += int64(n)
		if err != nil {
			return written, fmt.Errorf("could not write chunk: %w", err)
		}
		sr.ad = nil
	}

	sr.Close()
	return written, nil
}

// getCounter returns the counter part of the header as an integer.
func (sr *STREAMReader) getCounter() int {
	return int(sr.d.nonce[1]) ^ (int(sr.d.nonce[2]) << 8) ^ (int(sr.d.nonce[3]) << 16)
}
