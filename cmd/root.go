package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "s3-check",
	Short: "A tool to check various S3 bucket permissions",
	Long: `A tool to check various S3 bucket permissions including HEAD, LIST, GET-ACL, GET, WRITE, and DELETE operations for both authenticated and unauthenticated users.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(checkCmd)
}

