package compress

import (
	"fmt"
	"io"
	"os"

	"github.com/opencontainers/go-digest"
)

type StargzCompressionResult struct {
	CompressedBlob *StargzBlob
	TOCDigest      digest.Digest
}

// TarToStargz converts a tar archive to a stargz blob WITHOUT landmark files.
// This uses BuildNoLandmarks which produces a valid stargz layer with TOC
// but excludes .prefetch.landmark and .no.prefetch.landmark files.
func TarToStargz(tarPath string, chunkSize int) (*StargzCompressionResult, error) {
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

	opts := []BuildOption{
		WithBuildChunkSize(chunkSize),
	}

	blob, err := BuildNoLandmarks(sr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to build stargz blob: %w", err)
	}

	tocDigest := blob.TOCDigest()

	return &StargzCompressionResult{
		CompressedBlob: blob,
		TOCDigest:      tocDigest,
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
