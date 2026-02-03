package compress

// This file contains a modified version of estargz.Build that produces stargz layers
// without landmark files (.prefetch.landmark and .no.prefetch.landmark).
// Most functions are copied from github.com/containerd/stargz-snapshotter/estargz/build.go

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/containerd/stargz-snapshotter/estargz"
	"github.com/klauspost/compress/zstd"
	digest "github.com/opencontainers/go-digest"
)

// StargzBlob is an eStargz blob without landmark files.
// This is similar to estargz.Blob but created by BuildNoLandmarks.
type StargzBlob struct {
	io.ReadCloser
	diffID    digest.Digester
	tocDigest digest.Digest
}

// DiffID returns the digest of uncompressed blob.
// It is only valid to call DiffID after Close.
func (b *StargzBlob) DiffID() digest.Digest {
	return b.diffID.Digest()
}

// TOCDigest returns the digest of uncompressed TOC JSON.
func (b *StargzBlob) TOCDigest() digest.Digest {
	return b.tocDigest
}

// buildOptions holds options for the Build function.
// Copied from estargz with modifications.
type buildOptions struct {
	chunkSize        int
	compressionLevel int
	ctx              context.Context
}

// BuildOption is a functional option for Build.
type BuildOption func(o *buildOptions) error

// WithBuildChunkSize sets the chunk size for the stargz blob.
func WithBuildChunkSize(chunkSize int) BuildOption {
	return func(o *buildOptions) error {
		o.chunkSize = chunkSize
		return nil
	}
}

// WithBuildCompressionLevel sets the gzip compression level.
func WithBuildCompressionLevel(level int) BuildOption {
	return func(o *buildOptions) error {
		o.compressionLevel = level
		return nil
	}
}

// WithBuildContext sets the context for the build operation.
func WithBuildContext(ctx context.Context) BuildOption {
	return func(o *buildOptions) error {
		o.ctx = ctx
		return nil
	}
}

// buildEntry represents a tar entry during build.
// Copied from estargz.
type buildEntry struct {
	header  *tar.Header
	payload io.ReadSeeker
}

// buildTarFile manages a collection of tar entries.
// Copied from estargz.
type buildTarFile struct {
	index  map[string]*buildEntry
	stream []*buildEntry
}

// add adds an entry to the tar file.
// Copied from estargz.
func (f *buildTarFile) add(e *buildEntry) {
	if f.index == nil {
		f.index = make(map[string]*buildEntry)
	}
	f.index[cleanBuildEntryName(e.header.Name)] = e
	f.stream = append(f.stream, e)
}

// remove removes an entry by name.
// Copied from estargz.
func (f *buildTarFile) remove(name string) {
	name = cleanBuildEntryName(name)
	if f.index != nil {
		delete(f.index, name)
	}
	var filtered []*buildEntry
	for _, e := range f.stream {
		if cleanBuildEntryName(e.header.Name) == name {
			continue
		}
		filtered = append(filtered, e)
	}
	f.stream = filtered
}

// get retrieves an entry by name.
// Copied from estargz.
func (f *buildTarFile) get(name string) (e *buildEntry, ok bool) {
	if f.index == nil {
		return nil, false
	}
	e, ok = f.index[cleanBuildEntryName(name)]
	return
}

// dump returns all entries.
// Copied from estargz.
func (f *buildTarFile) dump() []*buildEntry {
	return f.stream
}

// cleanBuildEntryName normalizes entry names.
// Copied from estargz.
func cleanBuildEntryName(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// buildTempFiles manages temporary files during build.
// Copied from estargz.
type buildTempFiles struct {
	files       []*os.File
	filesMu     sync.Mutex
	cleanupOnce sync.Once
}

// newBuildTempFiles creates a new temp file manager.
// Copied from estargz.
func newBuildTempFiles() *buildTempFiles {
	return &buildTempFiles{}
}

// TempFile creates a new temporary file.
// Copied from estargz.
func (tf *buildTempFiles) TempFile(dir, pattern string) (*os.File, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	tf.filesMu.Lock()
	tf.files = append(tf.files, f)
	tf.filesMu.Unlock()
	return f, nil
}

// CleanupAll removes all temporary files.
// Copied from estargz.
func (tf *buildTempFiles) CleanupAll() (err error) {
	tf.cleanupOnce.Do(func() {
		err = tf.cleanupAllInner()
	})
	return
}

func (tf *buildTempFiles) cleanupAllInner() error {
	tf.filesMu.Lock()
	defer tf.filesMu.Unlock()
	var allErr []error
	for _, f := range tf.files {
		if err := f.Close(); err != nil {
			allErr = append(allErr, err)
		}
		if err := os.Remove(f.Name()); err != nil {
			allErr = append(allErr, err)
		}
	}
	tf.files = nil
	if len(allErr) > 0 {
		return allErr[0]
	}
	return nil
}

// buildCountReadSeeker tracks position while reading.
// Copied from estargz.
type buildCountReadSeeker struct {
	r    io.ReaderAt
	cPos *int64
	mu   sync.Mutex
}

// newBuildCountReadSeeker creates a new position-tracking reader.
// Copied from estargz.
func newBuildCountReadSeeker(r io.ReaderAt) (*buildCountReadSeeker, error) {
	pos := int64(0)
	return &buildCountReadSeeker{r: r, cPos: &pos}, nil
}

// Read implements io.Reader.
// Copied from estargz.
func (cr *buildCountReadSeeker) Read(p []byte) (int, error) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	n, err := cr.r.ReadAt(p, *cr.cPos)
	if err == nil {
		*cr.cPos += int64(n)
	}
	return n, err
}

// Seek implements io.Seeker.
// Copied from estargz.
func (cr *buildCountReadSeeker) Seek(offset int64, whence int) (int64, error) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	switch whence {
	default:
		return 0, fmt.Errorf("unknown whence: %v", whence)
	case io.SeekStart:
	case io.SeekCurrent:
		offset += *cr.cPos
	case io.SeekEnd:
		return 0, fmt.Errorf("unsupported whence: %v", whence)
	}
	if offset < 0 {
		return 0, fmt.Errorf("invalid offset")
	}
	*cr.cPos = offset
	return offset, nil
}

// currentPos returns the current position.
// Copied from estargz.
func (cr *buildCountReadSeeker) currentPos() int64 {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return *cr.cPos
}

// buildReadCloser combines a reader with a close function.
// Copied from estargz.
type buildReadCloser struct {
	io.Reader
	closeFunc func() error
}

// Close calls the close function.
// Copied from estargz.
func (rc buildReadCloser) Close() error {
	return rc.closeFunc()
}

// buildFileSectionReader creates a section reader for a file.
// Copied from estargz.
func buildFileSectionReader(file *os.File) (*io.SectionReader, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	return io.NewSectionReader(file, 0, info.Size()), nil
}

// decompressBuildBlob decompresses a blob if needed.
// Copied from estargz.
func decompressBuildBlob(org *io.SectionReader, tmp *buildTempFiles) (*io.SectionReader, error) {
	if org.Size() < 4 {
		return org, nil
	}
	src := make([]byte, 4)
	if _, err := org.Read(src); err != nil && err != io.EOF {
		return nil, err
	}
	var dR io.Reader
	if bytes.Equal([]byte{0x1F, 0x8B, 0x08}, src[:3]) {
		// gzip
		dgR, err := gzip.NewReader(io.NewSectionReader(org, 0, org.Size()))
		if err != nil {
			return nil, err
		}
		defer dgR.Close()
		dR = io.Reader(dgR)
	} else if bytes.Equal([]byte{0x28, 0xb5, 0x2f, 0xfd}, src[:4]) {
		// zstd
		dzR, err := zstd.NewReader(io.NewSectionReader(org, 0, org.Size()))
		if err != nil {
			return nil, err
		}
		defer dzR.Close()
		dR = io.Reader(dzR)
	} else {
		// uncompressed
		return io.NewSectionReader(org, 0, org.Size()), nil
	}
	b, err := tmp.TempFile("", "uncompresseddata")
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(b, dR); err != nil {
		return nil, err
	}
	return buildFileSectionReader(b)
}

var errBuildNotFound = errors.New("not found")

// importBuildTar reads a tar archive into a buildTarFile.
// Copied from estargz.
func importBuildTar(in io.ReaderAt) (*buildTarFile, error) {
	tf := &buildTarFile{}
	pw, err := newBuildCountReadSeeker(in)
	if err != nil {
		return nil, fmt.Errorf("failed to make position watcher: %w", err)
	}
	tr := tar.NewReader(pw)

	for {
		h, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to parse tar file, %w", err)
		}
		switch cleanBuildEntryName(h.Name) {
		case estargz.PrefetchLandmark, estargz.NoPrefetchLandmark:
			// Ignore existing landmark
			continue
		}

		if _, ok := tf.get(h.Name); ok {
			tf.remove(h.Name)
		}
		tf.add(&buildEntry{
			header:  h,
			payload: io.NewSectionReader(in, pw.currentPos(), h.Size),
		})
	}

	return tf, nil
}

// sortBuildEntriesNoLandmarks returns entries WITHOUT adding landmark files.
// Modified from estargz sortEntries - the key difference is no landmark addition.
func sortBuildEntriesNoLandmarks(in io.ReaderAt) ([]*buildEntry, error) {
	intar, err := importBuildTar(in)
	if err != nil {
		return nil, fmt.Errorf("failed to sort: %w", err)
	}

	// NOTE: This is the key modification - we do NOT add landmark entries.
	// Original estargz adds PrefetchLandmark or NoPrefetchLandmark at this point.
	// We skip prioritization as well since we don't need landmarks.

	return intar.dump(), nil
}

// readerFromBuildEntries creates a tar reader from entries.
// Copied from estargz.
func readerFromBuildEntries(entries ...*buildEntry) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		defer tw.Close()
		for _, entry := range entries {
			if err := tw.WriteHeader(entry.header); err != nil {
				pw.CloseWithError(fmt.Errorf("failed to write tar header: %v", err))
				return
			}
			if _, err := io.Copy(tw, entry.payload); err != nil {
				pw.CloseWithError(fmt.Errorf("failed to write tar payload: %v", err))
				return
			}
		}
		pw.Close()
	}()
	return pr
}

// BuildNoLandmarks builds a stargz blob WITHOUT landmark files.
// This is a modified version of estargz.Build that skips adding
// .prefetch.landmark and .no.prefetch.landmark files.
// The resulting blob is still a valid stargz layer with TOC.
//
// This uses single-threaded processing (no parallel build) to avoid
// needing to access internal estargz.Writer fields for combining.
func BuildNoLandmarks(tarBlob *io.SectionReader, opt ...BuildOption) (_ *StargzBlob, rErr error) {
	var opts buildOptions
	opts.compressionLevel = gzip.BestCompression
	for _, o := range opt {
		if err := o(&opts); err != nil {
			return nil, err
		}
	}

	layerFiles := newBuildTempFiles()
	ctx := opts.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			layerFiles.CleanupAll()
		}
	}()

	defer func() {
		if rErr != nil {
			if err := layerFiles.CleanupAll(); err != nil {
				rErr = fmt.Errorf("failed to cleanup tmp files: %v: %w", err, rErr)
			}
		}
		if cErr := ctx.Err(); cErr != nil {
			rErr = fmt.Errorf("error from context %q: %w", cErr, rErr)
		}
	}()

	tarBlob, err := decompressBuildBlob(tarBlob, layerFiles)
	if err != nil {
		return nil, err
	}

	// Use our modified sort function that doesn't add landmarks
	entries, err := sortBuildEntriesNoLandmarks(tarBlob)
	if err != nil {
		return nil, err
	}

	// Create output file for the stargz blob
	esgzFile, err := layerFiles.TempFile("", "esgzdata")
	if err != nil {
		return nil, err
	}

	// Use single writer (no parallel processing)
	sw := estargz.NewWriterLevel(esgzFile, opts.compressionLevel)
	sw.ChunkSize = opts.chunkSize

	// Append all tar entries
	if err := sw.AppendTar(readerFromBuildEntries(entries...)); err != nil {
		rErr = err
		return nil, err
	}

	// Close the writer - this writes the TOC and footer
	tocDgst, err := sw.Close()
	if err != nil {
		rErr = err
		return nil, err
	}

	// Seek back to beginning of file for reading
	if _, err := esgzFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	// Get the final blob size
	blobSR, err := buildFileSectionReader(esgzFile)
	if err != nil {
		return nil, err
	}

	// Calculate diffID by decompressing and hashing
	diffID := digest.Canonical.Digester()
	gzr, err := gzip.NewReader(io.NewSectionReader(esgzFile, 0, blobSR.Size()))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader for diffID: %w", err)
	}
	if _, err := io.Copy(diffID.Hash(), gzr); err != nil {
		gzr.Close()
		return nil, fmt.Errorf("failed to calculate diffID: %w", err)
	}
	gzr.Close()

	// Seek back to beginning for the final reader
	if _, err := esgzFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	return &StargzBlob{
		ReadCloser: buildReadCloser{
			Reader:    esgzFile,
			closeFunc: layerFiles.CleanupAll,
		},
		tocDigest: tocDgst,
		diffID:    diffID,
	}, nil
}
