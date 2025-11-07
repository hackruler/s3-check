package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"s3-check/internal/checker"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
)

var (
	fromFile  string
	fromStdin bool
	verbose   bool
	maxBucketWidth int
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check permissions for specific buckets",
	Long: `Check permissions for S3 buckets. Buckets can be specified in multiple ways:
1. As command line arguments: ./s3-check check bucket1 bucket2
2. From a file: ./s3-check check --file buckets.txt
3. From stdin: echo "bucket1" | ./s3-check check --stdin
4. All buckets: ./s3-check check (requires AWS permissions to list all buckets)`,
	RunE: runCheck,
}

func init() {
	checkCmd.Flags().StringVarP(&fromFile, "file", "f", "", "Read bucket names from file (one per line)")
	checkCmd.Flags().BoolVarP(&fromStdin, "stdin", "i", false, "Read bucket names from stdin (one per line)")
	checkCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed error messages for debugging")
}

func runCheck(cmd *cobra.Command, args []string) error {
	var buckets []string
	var err error

	// Check if stdin is a pipe (piped input)
	isStdinPipe := isStdinPipe()

	// Priority: explicit stdin flag > file > args > piped stdin > list all buckets
	if fromStdin {
		buckets, err = readFromStdin()
		if err != nil {
			return fmt.Errorf("error reading from stdin: %w", err)
		}
	} else if fromFile != "" {
		buckets, err = readFromFile(fromFile)
		if err != nil {
			return fmt.Errorf("error reading from file: %w", err)
		}
	} else if len(args) > 0 {
		buckets = args
	} else if isStdinPipe {
		// If stdin is piped and no other input specified, read from stdin
		buckets, err = readFromStdin()
		if err != nil {
			return fmt.Errorf("error reading from stdin: %w", err)
		}
		if len(buckets) == 0 {
			return fmt.Errorf("no buckets provided via stdin")
		}
	} else {
		// No input specified and stdin is not a pipe - list all buckets
		checker, err := checker.NewChecker()
		if err != nil {
			return fmt.Errorf("error initializing checker: %w", err)
		}
		buckets, err = checker.ListAllBuckets()
		if err != nil {
			return fmt.Errorf("error listing buckets: %w", err)
		}
	}

	if len(buckets) == 0 {
		return fmt.Errorf("no buckets to check")
	}

	// Calculate max bucket name width for dynamic column sizing
	maxBucketWidth = calculateMaxBucketWidth(buckets)
	// Ensure minimum width
	if maxBucketWidth < len("BUCKET") {
		maxBucketWidth = len("BUCKET")
	}

	checker, err := checker.NewChecker()
	if err != nil {
		return fmt.Errorf("error initializing checker: %w", err)
	}

	// Set verbose mode if requested
	checker.SetVerbose(verbose)

	// Print header once
	printHeader()

	// Stream results as they come in
	err = checker.CheckBucketsStream(buckets, printResult)
	if err != nil {
		return fmt.Errorf("error checking buckets: %w", err)
	}

	// Print legend at the end
	printLegend()
	return nil
}

func readFromStdin() ([]string, error) {
	var buckets []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			buckets = append(buckets, line)
		}
	}
	return buckets, scanner.Err()
}

func readFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var buckets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			buckets = append(buckets, line)
		}
	}
	return buckets, scanner.Err()
}

// isStdinPipe checks if stdin is a pipe or redirected input (not a terminal)
func isStdinPipe() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	
	// Check if stdin is a pipe or redirected input (not a character device/terminal)
	mode := stat.Mode()
	return (mode & os.ModeCharDevice) == 0
}

func calculateMaxBucketWidth(buckets []string) int {
	maxWidth := len("BUCKET")
	for _, bucket := range buckets {
		if len(bucket) > maxWidth {
			maxWidth = len(bucket)
		}
	}
	return maxWidth
}

func printHeader() {
	fmt.Println()
	// Use dynamic width for BUCKET column
	fmt.Printf("%-*s | %-8s | %-8s | %-9s | %-9s | %-10s | %-10s | %-9s | %-9s\n",
		maxBucketWidth, "BUCKET", "GET-ACL", "PUT-ACL", "ANON-GET", "AUTH-GET", "ANON-WRITE", "AUTH-WRITE", "ANON-DEL", "AUTH-DEL")
	// Create separator with dynamic width
	separator := strings.Repeat("-", maxBucketWidth) + "-+-" + 
		strings.Repeat("-", 8) + "-+-" + strings.Repeat("-", 8) + "-+-" +
		strings.Repeat("-", 9) + "-+-" + strings.Repeat("-", 9) + "-+-" + 
		strings.Repeat("-", 10) + "-+-" + strings.Repeat("-", 10) + "-+-" + 
		strings.Repeat("-", 9) + "-+-" + strings.Repeat("-", 9)
	fmt.Println(separator)
}

func printResult(result checker.BucketResult) {
	// Use dynamic width for bucket name column
	fmt.Printf("%-*s | %s | %s | %s | %s | %s | %s | %s | %s\n",
		maxBucketWidth, result.BucketName,
		colorizeStatus(result.GetACL, 8),
		colorizeStatus(result.PutACL, 8),
		colorizeStatus(result.AnonGet, 9),
		colorizeStatus(result.AuthGet, 9),
		colorizeStatus(result.AnonWrite, 10),
		colorizeStatus(result.AuthWrite, 10),
		colorizeStatus(result.AnonDel, 9),
		colorizeStatus(result.AuthDel, 9))
}

func colorizeStatus(status string, width int) string {
	color := colorRed
	if status == "OK" {
		color = colorGreen
	}
	// Pad the status to the specified width
	// ANSI codes are invisible, so we need to pad based on visible length
	padding := width - len(status)
	if padding > 0 {
		return fmt.Sprintf("%s%s%s%s", color, status, strings.Repeat(" ", padding), colorReset)
	}
	return fmt.Sprintf("%s%s%s", color, status, colorReset)
}

func printLegend() {
	fmt.Println()
	fmt.Println("Legend:")
	fmt.Println("  ANON - Anonymous (unauthenticated) access")
	fmt.Println("  AUTH - Authenticated access")
	fmt.Println()
}

