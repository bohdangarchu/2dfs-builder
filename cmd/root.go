package cmd

import (
	"fmt"
	"log"
	"os"
	"path"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "tdfs",
		Short: "Build a a 2dfs field ",
		Long:  `Requires a 2dfs.yaml file in the current directory or a path to a 2dfs.yaml file. Read docs at https://github.com/2DFS/2dfs-builder`,
	}
	homeDir, _     = os.UserHomeDir()
	homeDirFlag    string
	BlobStorePath  string
	IndexStorePath string
	KeysStorePath  string
)

func Execute() error {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().StringVar(&homeDirFlag, "home-dir", path.Join(homeDir, ".2dfs"), "home directory for tdfs data")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		log.Printf("TMPDIR=%s", os.TempDir())
		basePath := homeDirFlag
		BlobStorePath = path.Join(basePath, "blobs")
		IndexStorePath = path.Join(basePath, "index")
		KeysStorePath = path.Join(basePath, "uncompressed-keys")

		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			fmt.Print("Creating base path: " + basePath + "\n")
			if err := os.Mkdir(basePath, 0755); err != nil {
				return fmt.Errorf("error creating base path: %w", err)
			}
		}
		if _, err := os.Stat(BlobStorePath); os.IsNotExist(err) {
			os.Mkdir(BlobStorePath, 0755)
		}
		if _, err := os.Stat(KeysStorePath); os.IsNotExist(err) {
			os.Mkdir(KeysStorePath, 0755)
		}
		if _, err := os.Stat(IndexStorePath); os.IsNotExist(err) {
			os.Mkdir(IndexStorePath, 0755)
		}
		return nil
	}
	return rootCmd.Execute()
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}
