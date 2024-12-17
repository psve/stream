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

var (
	ErrModifiedStream  = errors.New("modified stream")
	ErrTruncatedStream = errors.New("truncated stream")
	ErrWriteAfterClose = errors.New("write after close")
)

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

	inLen := len(p)
	for len(p) > 0 {
		switch {
		case len(sw.d.chunk) == 0 && len(p) >= ChunkSize:
			// If there's nothing in our buffer, and we could buffer an entire chunk, just use
			// p as input directly.
			if err := sw.writeChunk(p[:ChunkSize]); err != nil {
				return inLen - len(p), err
			}
			p = p[ChunkSize:]
		case len(sw.d.chunk) < ChunkSize:
			// If we don't have a full chunk buffer yet, buffer as much as possible. Note that
			// the buffer always has capacity ChunkSize, so this doesn't allocate.
			canBuffer := min(len(p), ChunkSize-len(sw.d.chunk))
			sw.d.chunk = append(sw.d.chunk, p[:canBuffer]...)
			p = p[canBuffer:]
		case len(sw.d.chunk) == ChunkSize:
			// We have filled up our plaintext buffer, write the next chunk.
			if err := sw.writeChunk(sw.d.chunk); err != nil {
				return inLen - len(p), err
			}
		}
	}

	return inLen, nil
}

// Close flushes all data to the underlying io.Writer and closes the stream. Subsequent
// calls to Close is a no-op.
func (sw *STREAMWriter) Close() error {
	if sw.closed {
		return nil
	}

	// Indicate that this is the last chunk and write it.
	sw.d.nonce[0] = 1
	if err := sw.writeChunk(sw.d.chunk); err != nil {
		return err
	}

	clear(sw.d.nonce[:counterOverhead])
	sw.dataPool.Put(sw.d)
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
	for sw.d.nonce[0] != 1 {
		n, readErr := io.ReadFull(r, sw.d.chunk[:ChunkSize])
		read += int64(n)
		if readErr != nil {
			// No matter which error occurs (i.e. it could be an expected EOF) we cannot read
			// any more data, so we mark this as the last chunk.
			sw.d.nonce[0] = 1
		}
		if err := sw.writeChunk(sw.d.chunk[:n]); err != nil {
			return read, err
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return read, fmt.Errorf("could not read chunk: %w", readErr)
		}
	}

	clear(sw.d.nonce[:counterOverhead])
	sw.dataPool.Put(sw.d)
	sw.closed = true
	return read, nil
}

// writeChunk writes the current nonce and the encrypted chunk to the underlying writer,
// and prepares for the next chunk.
func (sw *STREAMWriter) writeChunk(chunk []byte) error {
	if _, err := sw.w.Write(sw.d.nonce); err != nil {
		return fmt.Errorf("could not write nonce: %w", err)
	}
	if _, err := sw.w.Write(sw.aead.Seal(sw.d.chunk[:0], sw.d.nonce, chunk, sw.ad)); err != nil {
		return fmt.Errorf("could not write chunk: %w", err)
	}

	sw.ad, sw.d.chunk = nil, sw.d.chunk[:0]
	sw.increaseCounter()
	return nil
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

	inLen := len(p)
	for len(p) > 0 {
		switch {
		case sr.d.nonce[0] == 1 && sr.chunkIdx == len(sr.d.chunk):
			// We have read the last chunk and used the entire plaintext buffer. There's
			// nothing left to do.
			return inLen - len(p), io.EOF
		case sr.chunkIdx < ChunkSize:
			// We still have plaintext available in the buffer. Copy as many bytes as
			// possible.
			copied := copy(p, sr.d.chunk[sr.chunkIdx:])
			p = p[copied:]
			sr.chunkIdx += copied
		case sr.chunkIdx == ChunkSize:
			// We havn't read the last chunk yet, but we have run out of plaintext buffer. Try
			// to read the next chunk.
			if err := sr.readChunk(); err != nil {
				return inLen - len(p), err
			}
		}
	}

	return inLen, nil
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

// WriteTo will consume all data from the underlying io.Reader and write the decrypted
// result to w.
func (sr *STREAMReader) WriteTo(w io.Writer) (int64, error) {
	if sr.closed {
		return 0, io.EOF
	}

	written := int64(0)

	if sr.chunkIdx < ChunkSize {
		// STREAMReader.Read was called at some point and we still have plaintext available
		// in the buffer. Write the rest of the chunk so we can start from a new chunk
		// below.
		n, err := w.Write(sr.d.chunk[sr.chunkIdx:])
		written += int64(n)
		if err != nil {
			return written, fmt.Errorf("could not write chunk: %w", err)
		}
		sr.chunkIdx += n
	}

	for sr.d.nonce[0] != 1 {
		if err := sr.readChunk(); err != nil {
			return written, err
		}

		n, err := w.Write(sr.d.chunk)
		written += int64(n)
		if err != nil {
			return written, fmt.Errorf("could not write chunk: %w", err)
		}
	}

	sr.Close()
	return written, nil
}

// readChunk reads the next chunk from the underlying io.Reader. It is assumed that
// we're at the start of a new chunk.
func (sr *STREAMReader) readChunk() error {
	if _, err := io.ReadFull(sr.r, sr.d.nonce); err != nil {
		return fmt.Errorf("could not read nonce: %w", err)
	}
	if sr.chunkCount != sr.getCounter() {
		return ErrModifiedStream
	}

	// Growing the slice here to make room for the ciphertext chunk. This doesn't require
	// allocation as sr.d.chunk always has capacity ChunkSize+sr.aead.Overhead().
	sr.d.chunk = sr.d.chunk[:ChunkSize+sr.aead.Overhead()]

	n, err := io.ReadFull(sr.r, sr.d.chunk)
	if sr.d.nonce[0] != 1 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		return ErrTruncatedStream
	}
	sr.d.chunk, err = sr.aead.Open(sr.d.chunk[:0], sr.d.nonce, sr.d.chunk[:n], sr.ad)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	sr.ad, sr.chunkIdx = nil, 0
	sr.chunkCount++
	return nil
}

// getCounter returns the counter part of the header as an integer.
func (sr *STREAMReader) getCounter() int {
	return int(sr.d.nonce[1]) ^ (int(sr.d.nonce[2]) << 8) ^ (int(sr.d.nonce[3]) << 16)
}
