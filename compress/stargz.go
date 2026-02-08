package compress

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/containerd/stargz-snapshotter/estargz"
	"github.com/opencontainers/go-digest"
)

var pigzPath = findCmdPath("pigz")
var gzipPath = findCmdPath("gzip")

type StargzCompressionResult struct {
	CompressedBlob *estargz.Blob
	TOCDigest      digest.Digest
}

func GzipHelperPath(helper string) string {
	switch helper {
	case "pigz":
		return pigzPath
	case "gzip":
		return gzipPath
	default:
		return ""
	}
}

func TarToStargz(tarPath string, chunkSize int, gzipHelperPath string) (*StargzCompressionResult, error) {
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
	}

	if gzipHelperPath != "" {
		opts = append(opts, estargz.WithGzipHelperFunc(getCmdGzipHelperFunc(gzipHelperPath)))
	}

	blob, err := estargz.Build(sr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to build estargz blob: %w", err)
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

// estargz gzip.go
func getCmdGzipHelperFunc(cmdPath string) estargz.GzipHelperFunc {
	return func(in io.Reader) (io.ReadCloser, error) {
		cmd := exec.Command(cmdPath, "-d", "-c")

		readCloser, writer := io.Pipe()
		cmd.Stdin = in
		cmd.Stdout = writer

		var errBuf bytes.Buffer
		cmd.Stderr = &errBuf

		if err := cmd.Start(); err != nil {
			writer.Close()
			return nil, err
		}

		go func() {
			if err := cmd.Wait(); err != nil {
				writer.CloseWithError(fmt.Errorf("gzip helper failed, %s: %s", err, errBuf.String()))
			}
			writer.Close()
		}()

		return readCloser, nil
	}
}

func findCmdPath(cmd string) string {
	path, err := exec.LookPath(cmd)
	if err != nil {
		return ""
	}
	return path
}
