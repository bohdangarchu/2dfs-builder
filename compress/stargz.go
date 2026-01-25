package compress

import (
	"fmt"
	"io"
	"os"

	"github.com/containerd/stargz-snapshotter/estargz"
	"github.com/opencontainers/go-digest"
)

// StargzCompressionResult holds the results of stargz compression
type StargzCompressionResult struct {
	CompressedBlob *estargz.Blob
	TOCDigest      digest.Digest
}

// TarToStargz compresses a TAR file to eStargz format with the given options
func TarToStargz(tarPath string, chunkSize int, prefetchFiles []string) (*StargzCompressionResult, error) {
	tarFile, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}
	defer tarFile.Close()

	stat, err := tarFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat tar file: %w", err)
	}

	// Create a section reader for the entire file
	sr := io.NewSectionReader(tarFile, 0, stat.Size())

	// Build estargz options
	opts := []estargz.Option{
		estargz.WithChunkSize(chunkSize),
	}

	if len(prefetchFiles) > 0 {
		opts = append(opts, estargz.WithPrioritizedFiles(prefetchFiles))
	}

	// Build the estargz blob
	blob, err := estargz.Build(sr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to build estargz blob: %w", err)
	}

	// Get blob info
	tocDigest := blob.TOCDigest()

	return &StargzCompressionResult{
		CompressedBlob: blob,
		TOCDigest:      tocDigest,
	}, nil
}

// CalculateStargzDigest calculates the SHA256 digest of a stargz blob reader
func CalculateStargzDigest(reader io.Reader) (string, int64, error) {
	hasher := digest.SHA256.Digester()
	size, err := io.Copy(hasher.Hash(), reader)
	if err != nil {
		return "", 0, err
	}
	return hasher.Digest().Encoded(), size, nil
}