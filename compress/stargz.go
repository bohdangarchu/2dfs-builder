package compress

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/containerd/stargz-snapshotter/estargz"
	"github.com/opencontainers/go-digest"
)

type StargzCompressionResult struct {
	CompressedReader io.ReadCloser
	DiffID           string
	TOCDigest        digest.Digest
}

type tempFileReadCloser struct {
	*os.File
}

func (t *tempFileReadCloser) Close() error {
	err := t.File.Close()
	os.Remove(t.File.Name())
	return err
}

func TarToStargz(tarPath string, chunkSize int, compressionLevel int) (*StargzCompressionResult, error) {
	tarFile, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}
	defer tarFile.Close()

	stat, err := tarFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat tar file: %w", err)
	}

	sr := io.NewSectionReader(tarFile, 0, stat.Size())

	opts := []estargz.Option{
		estargz.WithChunkSize(chunkSize),
		estargz.WithIncludeLandmarks(false),
		estargz.WithCompressionLevel(compressionLevel),
	}

	start := time.Now()
	blob, err := estargz.Build(sr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to build estargz blob: %w", err)
	}
	log.Printf("estargz.Build took %s", time.Since(start))

	// Buffer the blob to a temp file so we can inspect the TOC and still return a reader.
	// Draining the pipe also finalises the DiffID digest in the background goroutine.
	tmpFile, err := os.CreateTemp("", "stargz-blob-*")
	if err != nil {
		blob.Close()
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	if _, err := io.Copy(tmpFile, blob); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		blob.Close()
		return nil, fmt.Errorf("failed to buffer stargz blob: %w", err)
	}
	// Close blob to clean up estargz temp files; DiffID is valid now that the pipe is drained.
	diffID := blob.DiffID().Encoded()
	blob.Close()

	// Parse and print the uncompressed TOC JSON.
	blobSize, err := tmpFile.Seek(0, io.SeekEnd)
	if err == nil {
		if tocOffset, footerSize, err := estargz.OpenFooter(io.NewSectionReader(tmpFile, 0, blobSize)); err == nil {
			tocSize := blobSize - tocOffset - footerSize
			tocBytes := make([]byte, tocSize)
			if _, err := tmpFile.ReadAt(tocBytes, tocOffset); err == nil {
				d := new(estargz.GzipDecompressor)
				if tocJSON, err := d.DecompressTOC(bytes.NewReader(tocBytes)); err == nil {
					defer tocJSON.Close()
					raw, _ := io.ReadAll(tocJSON)
					log.Printf("TOC JSON: %s", string(raw))
				}
			}
		}
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to seek temp file: %w", err)
	}

	return &StargzCompressionResult{
		CompressedReader: &tempFileReadCloser{File: tmpFile},
		DiffID:           diffID,
		TOCDigest:        blob.TOCDigest(),
	}, nil
}

func CalculateStargzDigest(reader io.Reader) (string, int64, error) {
	hasher := digest.SHA256.Digester()
	size, err := io.Copy(hasher.Hash(), reader)
	if err != nil {
		return "", 0, err
	}
	return hasher.Digest().Encoded(), size, nil
}
