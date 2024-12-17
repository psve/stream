package stream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"testing"
)

func must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

func setupSTREAM() *STREAM {
	key := randomData(16)
	aes := must(aes.NewCipher(key))
	gcm := must(cipher.NewGCM(aes))
	return NewSTREAM(gcm)
}

func randomData(length int) []byte {
	data := make([]byte, length)
	must(rand.Read(data))
	return data
}

func TestSealOpen(t *testing.T) {
	stream := setupSTREAM()

	cases := []struct {
		plaintext      int64
		additionalData bool
	}{
		// Tests with no associated data
		{
			plaintext:      0, // Zero length data
			additionalData: false,
		},
		{
			plaintext:      ChunkSize - 1024, // Less than one chunk
			additionalData: false,
		},
		{
			plaintext:      3 * ChunkSize, // Only full chunks
			additionalData: false,
		},
		{
			plaintext:      3*ChunkSize + 1024, // Partial last chunk
			additionalData: false,
		},
		// Tests with associated data
		{
			plaintext:      0, // Zero length data
			additionalData: true,
		},
		{
			plaintext:      ChunkSize - 1024, // Less than one chunk
			additionalData: true,
		},
		{
			plaintext:      3 * ChunkSize, // Only full chunks
			additionalData: true,
		},
		{
			plaintext:      3*ChunkSize + 1024, // Partial last chunk
			additionalData: true,
		},
	}

	for i, c := range cases {
		plaintext := io.LimitReader(rand.Reader, c.plaintext)
		var additionalData []byte
		if c.additionalData {
			additionalData = randomData(1024)
		}

		ciphertext := new(bytes.Buffer)
		if err := stream.Seal(ciphertext, plaintext, additionalData); err != nil {
			t.Fatalf("(%d) encryption failed: %s", i, err)
		}
		decrypted := new(bytes.Buffer)
		if err := stream.Open(decrypted, ciphertext, additionalData); err != nil {
			t.Fatalf("(%d) decryption failed: %s", i, err)
		}
		if decrypted.Len() != int(c.plaintext) {
			t.Fatalf("(%d) decryption length is wrong: %d != %d", i, decrypted.Len(), int(c.plaintext))
		}
	}
}

func TestOverhead(t *testing.T) {
	stream := setupSTREAM()

	cases := []struct {
		length   int
		expected int
	}{
		{0, 28},
		{1, 28},
		{ChunkSize - 1, 28},
		{ChunkSize, 28},
		{ChunkSize + 1, 56},
		{2*ChunkSize - 1, 56},
	}

	for i, c := range cases {
		if stream.Overhead(c.length) != c.expected {
			t.Fatalf("(%d) wrong overhead: %d != %d", i, stream.Overhead(c.length), c.expected)
		}
	}
}

type testErrReader struct {
	io.Reader
	limit int
	read  int
}

func (r *testErrReader) Read(b []byte) (int, error) {
	if r.read+len(b) > r.limit {
		canRead := r.limit - r.read
		n, _ := r.Reader.Read(b[:canRead])
		r.read += n
		return n, errors.New("test error")
	}
	n, err := r.Reader.Read(b)
	r.read += n
	return n, err
}

func TestErroredStream(t *testing.T) {
	stream := setupSTREAM()
	plaintext := randomData(3*ChunkSize + 1024)
	additionalData := randomData(1024)

	// errPlaintext will error before reading the whole plaintext. We should still be able
	// to decrypt what was read.
	errPlaintext := &testErrReader{
		Reader: bytes.NewReader(plaintext),
		limit:  3*ChunkSize - 1024,
	}

	ciphertext := new(bytes.Buffer)
	w := must(stream.NewWriter(ciphertext, additionalData))
	n, err := w.ReadFrom(errPlaintext)
	if err == nil {
		t.Fatalf("expected ReadFrom to error")
	}
	if n != int64(errPlaintext.limit) {
		t.Fatalf("wrong number of bytes read")
	}

	decrypted := new(bytes.Buffer)
	if err := stream.Open(decrypted, ciphertext, additionalData); err != nil {
		t.Fatalf("decryption failed: %s", err)
	}
	if !bytes.Equal(decrypted.Bytes(), plaintext[:errPlaintext.limit]) {
		t.Fatal("wrong decryption result")
	}
}

func TestSwapChunksOpen(t *testing.T) {
	stream := setupSTREAM()
	plaintext := io.LimitReader(rand.Reader, 3*ChunkSize)
	ciphertext := new(bytes.Buffer)
	if err := stream.Seal(ciphertext, plaintext, nil); err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	// Switch two chunks
	encryptedChunkSize := stream.aead.NonceSize() + ChunkSize + stream.aead.Overhead()
	buf := ciphertext.Bytes()
	chunkZero := slices.Clone(buf[:encryptedChunkSize])
	chunkOne := slices.Clone(buf[encryptedChunkSize : 2*encryptedChunkSize])
	copy(buf, chunkOne)
	copy(buf[encryptedChunkSize:], chunkZero)

	if err := stream.Open(io.Discard, ciphertext, nil); err == nil {
		t.Fatal("decryption with swapped chunks should fail")
	}
}

func TestSwapChunksRead(t *testing.T) {
	stream := setupSTREAM()
	plaintext := io.LimitReader(rand.Reader, 3*ChunkSize)
	ciphertext := new(bytes.Buffer)
	if err := stream.Seal(ciphertext, plaintext, nil); err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	// Switch two chunks
	encryptedChunkSize := stream.aead.NonceSize() + ChunkSize + stream.aead.Overhead()
	buf := ciphertext.Bytes()
	chunkZero := slices.Clone(buf[:encryptedChunkSize])
	chunkOne := slices.Clone(buf[encryptedChunkSize : 2*encryptedChunkSize])
	copy(buf, chunkOne)
	copy(buf[encryptedChunkSize:], chunkZero)

	r := stream.NewReader(ciphertext, nil)
	if _, err := r.Read(make([]byte, 3*ChunkSize)); err == nil {
		t.Fatal("decryption with swapped chunks should fail")
	}
}

func TestDropMiddleChunkOpen(t *testing.T) {
	stream := setupSTREAM()
	plaintext := io.LimitReader(rand.Reader, 3*ChunkSize)
	ciphertext := new(bytes.Buffer)
	if err := stream.Seal(ciphertext, plaintext, nil); err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	// Drop the second chunk
	encryptedChunkSize := stream.aead.NonceSize() + ChunkSize + stream.aead.Overhead()
	buf := ciphertext.Bytes()
	copy(buf[encryptedChunkSize:], buf[len(buf)-encryptedChunkSize:])
	ciphertext.Truncate(len(buf) - encryptedChunkSize)

	if err := stream.Open(io.Discard, ciphertext, nil); err == nil {
		t.Fatal("decryption with dropped chunk should fail")
	}
}

func TestDropMiddleChunkRead(t *testing.T) {
	stream := setupSTREAM()
	plaintext := io.LimitReader(rand.Reader, 3*ChunkSize)
	ciphertext := new(bytes.Buffer)
	if err := stream.Seal(ciphertext, plaintext, nil); err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	// Drop the second chunk
	encryptedChunkSize := stream.aead.NonceSize() + ChunkSize + stream.aead.Overhead()
	buf := ciphertext.Bytes()
	copy(buf[encryptedChunkSize:], buf[len(buf)-encryptedChunkSize:])
	ciphertext.Truncate(len(buf) - encryptedChunkSize)

	r := stream.NewReader(ciphertext, nil)
	if _, err := r.Read(make([]byte, 3*ChunkSize)); err == nil {
		t.Fatal("decryption with dropped chunk should fail")
	}
}

func TestDropLastChunkOpen(t *testing.T) {
	stream := setupSTREAM()
	plaintext := io.LimitReader(rand.Reader, 3*ChunkSize)
	ciphertext := new(bytes.Buffer)
	if err := stream.Seal(ciphertext, plaintext, nil); err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	// Drop the last chunk
	encryptedChunkSize := stream.aead.NonceSize() + ChunkSize + stream.aead.Overhead()
	ciphertext.Truncate(ciphertext.Len() - encryptedChunkSize)

	if err := stream.Open(io.Discard, ciphertext, nil); err == nil {
		t.Fatal("decryption with dropped last chunk should fail")
	}
}

func TestDropLastChunkRead(t *testing.T) {
	stream := setupSTREAM()
	plaintext := io.LimitReader(rand.Reader, 3*ChunkSize)
	ciphertext := new(bytes.Buffer)
	if err := stream.Seal(ciphertext, plaintext, nil); err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	// Drop the last chunk
	encryptedChunkSize := stream.aead.NonceSize() + ChunkSize + stream.aead.Overhead()
	ciphertext.Truncate(ciphertext.Len() - encryptedChunkSize)

	r := stream.NewReader(ciphertext, nil)
	if _, err := r.Read(make([]byte, 3*ChunkSize)); err == nil {
		t.Fatal("decryption with dropped last chunk should fail")
	}
}

func TestWrongAdditionalDataOpen(t *testing.T) {
	stream := setupSTREAM()
	plaintext := io.LimitReader(rand.Reader, 3*ChunkSize)
	additionalData := randomData(1024)
	ciphertext := new(bytes.Buffer)
	if err := stream.Seal(ciphertext, plaintext, additionalData); err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	// Manipulate associated data
	additionalData[0] ^= 42
	if err := stream.Open(io.Discard, ciphertext, nil); err == nil {
		t.Fatal("decryption with dropped last chunk should fail")
	}
}

func TestWrongAdditionalDataRead(t *testing.T) {
	stream := setupSTREAM()
	plaintext := io.LimitReader(rand.Reader, 3*ChunkSize)
	additionalData := randomData(1024)
	ciphertext := new(bytes.Buffer)
	if err := stream.Seal(ciphertext, plaintext, additionalData); err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	// Manipulate associated data
	additionalData[0] ^= 42
	r := stream.NewReader(ciphertext, nil)
	if _, err := r.Read(make([]byte, 3*ChunkSize)); err == nil {
		t.Fatal("decryption with dropped last chunk should fail")
	}
}

func TestPipe(t *testing.T) {
	key := randomData(16)
	aes := must(aes.NewCipher(key))
	gcm := must(cipher.NewGCM(aes))

	encrypter := NewSTREAM(gcm)
	decrypter := NewSTREAM(gcm)

	plaintext := randomData(3*ChunkSize + 1024)
	additionalData := randomData(1024)
	decrypted := new(bytes.Buffer)

	r, w := io.Pipe()
	go func() {
		_ = encrypter.Seal(w, bytes.NewReader(plaintext), additionalData)
		w.Close()
	}()

	err := decrypter.Open(decrypted, r, additionalData)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatal("decryption result not equal to plaintext")
	}
}

func TestWriter(t *testing.T) {
	stream := setupSTREAM()

	cases := []struct {
		plaintext      int64
		additionalData bool
	}{
		// Tests with no associated data
		{
			plaintext:      0, // Zero length data
			additionalData: false,
		},
		{
			plaintext:      ChunkSize - 1024, // Less than one chunk
			additionalData: false,
		},
		{
			plaintext:      3 * ChunkSize, // Only full chunks
			additionalData: false,
		},
		{
			plaintext:      3*ChunkSize + 1024, // Partial last chunk
			additionalData: false,
		},
		// Tests with associated data
		{
			plaintext:      0, // Zero length data
			additionalData: true,
		},
		{
			plaintext:      ChunkSize - 1024, // Less than one chunk
			additionalData: true,
		},
		{
			plaintext:      3 * ChunkSize, // Only full chunks
			additionalData: true,
		},
		{
			plaintext:      3*ChunkSize + 1024, // Partial last chunk
			additionalData: true,
		},
	}

	for i, c := range cases {
		plaintext := randomData(int(c.plaintext))
		var additionalData []byte
		if c.additionalData {
			additionalData = randomData(1024)
		}
		ciphertext := new(bytes.Buffer)

		w := must(stream.NewWriter(ciphertext, additionalData))
		n, err := w.Write(plaintext)
		if err != nil {
			t.Fatalf("(%d) encryption failed: %s", i, err)
		}
		if n != len(plaintext) {
			t.Fatalf("(%d) short write", i)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("(%d) close failed: %v", i, err)
		}

		decrypted := new(bytes.Buffer)
		if err := stream.Open(decrypted, ciphertext, additionalData); err != nil {
			t.Fatalf("(%d) decryption failed: %v", i, err)
		}
		if !bytes.Equal(plaintext, decrypted.Bytes()) {
			t.Fatalf("(%d) wrong decryption result", i)
		}
	}
}

func TestGradualWrite(t *testing.T) {
	stream := setupSTREAM()
	additionalData := randomData(1024)
	ciphertext := new(bytes.Buffer)

	w := must(stream.NewWriter(ciphertext, additionalData))
	written := 0
	for written < 3*ChunkSize+1024 {
		n, _ := w.Write(randomData(1024))
		written += n
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	decrypted := new(bytes.Buffer)
	err := stream.Open(decrypted, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
}

func TestWriterErr(t *testing.T) {
	stream := setupSTREAM()
	additionalData := randomData(1024)
	_, closedWriter := io.Pipe()
	closedWriter.CloseWithError(errors.New("test error"))

	w := must(stream.NewWriter(closedWriter, additionalData))
	if _, err := w.Write(randomData(ChunkSize + 1)); err == nil {
		t.Fatalf("writing should have failed")
	}
	if err := w.Close(); err == nil {
		t.Fatalf("Close should have failed")
	}
}

func TestReader(t *testing.T) {
	stream := setupSTREAM()

	cases := []struct {
		plaintext      int64
		additionalData bool
	}{
		// Tests with no associated data
		{
			plaintext:      0, // Zero length data
			additionalData: false,
		},
		{
			plaintext:      ChunkSize - 1024, // Less than one chunk
			additionalData: false,
		},
		{
			plaintext:      3 * ChunkSize, // Only full chunks
			additionalData: false,
		},
		{
			plaintext:      3*ChunkSize + 1024, // Partial last chunk
			additionalData: false,
		},
		// Tests with associated data
		{
			plaintext:      0, // Zero length data
			additionalData: true,
		},
		{
			plaintext:      ChunkSize - 1024, // Less than one chunk
			additionalData: true,
		},
		{
			plaintext:      3 * ChunkSize, // Only full chunks
			additionalData: true,
		},
		{
			plaintext:      3*ChunkSize + 1024, // Partial last chunk
			additionalData: true,
		},
	}

	for i, c := range cases {
		plaintext := randomData(int(c.plaintext))
		var additionalData []byte
		if c.additionalData {
			additionalData = randomData(1024)
		}

		ciphertext := new(bytes.Buffer)
		if err := stream.Seal(ciphertext, bytes.NewBuffer(plaintext), additionalData); err != nil {
			t.Fatalf("(%d) encryption failed: %s", i, err)
		}

		r := stream.NewReader(ciphertext, additionalData)
		decrypted := make([]byte, c.plaintext)
		n, err := r.Read(decrypted)
		if err != nil {
			t.Fatalf("(%d) decryption failed: %s", i, err)
		}
		if n != len(plaintext) {
			t.Fatalf("(%d) short read", i)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("(%d) close failed: %v", i, err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("(%d) wrong decryption result", i)
		}
	}
}

func TestGradualRead(t *testing.T) {
	stream := setupSTREAM()
	additionalData := randomData(1024)
	plaintext := randomData(3*ChunkSize + 1024)
	ciphertext := new(bytes.Buffer)
	err := stream.Seal(ciphertext, bytes.NewBuffer(plaintext), additionalData)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	decrypted := make([]byte, 0, len(plaintext))
	buf := make([]byte, 1024)
	r := stream.NewReader(ciphertext, additionalData)
	for {
		n, err := r.Read(buf)
		decrypted = append(decrypted, buf[:n]...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("wrong decryption result")
	}
}

func TestReadOversizedSlice(t *testing.T) {
	stream := setupSTREAM()
	plaintext := randomData(3*ChunkSize + 1024)
	additionalData := randomData(1024)

	ciphertext := new(bytes.Buffer)
	if err := stream.Seal(ciphertext, bytes.NewBuffer(plaintext), additionalData); err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	r := stream.NewReader(ciphertext, additionalData)
	decrypted := make([]byte, 4*ChunkSize)
	n, err := r.Read(decrypted)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("decryption failed: %s", err)
	}
	if n != len(plaintext) {
		t.Fatalf("short read: %d < %d", n, len(plaintext))
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted[:n]) {
		t.Fatalf("wrong decryption result")
	}
}

// Test the case where STREAMReader.Read was used to consume part of the last chunk, and
// STREAMReader.WriteTo is then used to consume the rest.
func TestReaderReadBeforeWriteTo(t *testing.T) {
	cases := []int{ChunkSize - 1024, 3 * ChunkSize, 3*ChunkSize + 1024}

	for i, c := range cases {
		stream := setupSTREAM()
		additionalData := randomData(1024)
		plaintext := randomData(c)
		ciphertext := new(bytes.Buffer)
		err := stream.Seal(ciphertext, bytes.NewBuffer(plaintext), additionalData)
		if err != nil {
			t.Fatalf("(%d) encryption failed: %v", i, err)
		}

		decrypted := make([]byte, 1024)
		r := stream.NewReader(ciphertext, additionalData)

		// Consume 1024 bytes of the first chunk using Read.
		n, err := r.Read(decrypted)
		if err != nil {
			t.Fatalf("(%d) decryption failed: %s", i, err)
		}
		if n != len(decrypted) {
			t.Fatalf("(%d) short read: %d < %d", i, n, len(plaintext))
		}

		// Consume the rest using WriteTo.
		buf := new(bytes.Buffer)
		written, err := r.WriteTo(buf)
		if err != nil {
			t.Fatalf("(%d) decryption failed: %s", i, err)
		}
		if written != int64(c-len(decrypted)) {
			t.Fatalf("(%d) short read: %d < %d", i, n, len(plaintext))
		}
		decrypted = append(decrypted, buf.Bytes()...) //nolint:makezero

		if err := r.Close(); err != nil {
			t.Fatalf("(%d) close failed: %v", i, err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("(%d) wrong decryption result", i)
		}
	}
}

func TestReaderErr(t *testing.T) {
	stream := setupSTREAM()
	additionalData := randomData(1024)
	closedReader, _ := io.Pipe()
	closedReader.CloseWithError(errors.New("test error"))

	r := stream.NewReader(closedReader, additionalData)
	if _, err := r.Read(make([]byte, ChunkSize)); err == nil {
		t.Fatalf("reading should have failed")
	}
}

func BenchmarkSealAEAD(b *testing.B) {
	key := randomData(16)
	aes := must(aes.NewCipher(key))
	aead := must(cipher.NewGCM(aes))

	nonce := randomData(aead.NonceSize())
	plaintext := randomData(10*ChunkSize + 1024)
	additionalData := randomData(1024)
	ciphertext := randomData(len(plaintext) + aead.Overhead())

	b.SetBytes(int64(len(plaintext) + len(additionalData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext = aead.Seal(ciphertext[:0], nonce, plaintext, additionalData)
	}
}

func BenchmarkOpenAEAD(b *testing.B) {
	key := randomData(16)
	aes := must(aes.NewCipher(key))
	aead := must(cipher.NewGCM(aes))

	nonce := randomData(aead.NonceSize())
	plaintext := randomData(10*ChunkSize + 1024)
	additionalData := randomData(1024)

	ciphertext := make([]byte, len(plaintext)+aead.Overhead())
	ciphertext = aead.Seal(ciphertext[:0], nonce, plaintext, additionalData)

	b.SetBytes(int64(len(ciphertext) + len(additionalData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		plaintext, err = aead.Open(plaintext[:0], nonce, ciphertext, additionalData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSealSTREAM(b *testing.B) {
	stream := setupSTREAM()

	plaintext := randomData(10*ChunkSize + 1024)
	additionalData := randomData(1024)

	b.SetBytes(int64(len(plaintext) + len(additionalData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		r := bytes.NewReader(plaintext)
		b.StartTimer()
		err := stream.Seal(io.Discard, r, additionalData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpenSTREAM(b *testing.B) {
	stream := setupSTREAM()

	plaintext := randomData(10*ChunkSize + 1024)
	additionalData := randomData(1024)

	w := new(bytes.Buffer)
	_ = stream.Seal(w, bytes.NewReader(plaintext), additionalData)
	ciphertext := w.Bytes()

	b.SetBytes(int64(len(ciphertext) + len(additionalData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		r := bytes.NewReader(ciphertext)
		b.StartTimer()
		err := stream.Open(io.Discard, r, additionalData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriter(b *testing.B) {
	stream := setupSTREAM()

	plaintext := randomData(10*ChunkSize + 1024)

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		w := must(stream.NewWriter(io.Discard, nil))
		b.StartTimer()
		n, err := w.Write(plaintext)
		if n != len(plaintext) {
			b.Fatal("short write")
		}
		if err != nil {
			b.Fatal(err)
		}
		if err = w.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReader(b *testing.B) {
	stream := setupSTREAM()

	plaintext := randomData(10*ChunkSize + 1024)

	ciphertext := new(bytes.Buffer)
	sr := must(stream.NewWriter(ciphertext, nil))
	_, _ = sr.Write(plaintext)
	sr.Close()

	buf := make([]byte, len(plaintext))

	b.SetBytes(int64(len(ciphertext.Bytes())))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		r := stream.NewReader(bytes.NewReader(ciphertext.Bytes()), nil)
		b.StartTimer()

		for _, err := r.Read(buf); !errors.Is(err, io.EOF); _, err = r.Read(buf) {
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}
