package checker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// Delay between bucket checks to avoid rate limiting
	bucketCheckDelay = 100 * time.Millisecond
)

type Checker struct {
	ctx     context.Context
	verbose bool
}

type BucketResult struct {
	BucketName string
	GetACL     string
	PutACL     string
	AnonGet    string
	AuthGet    string
	AnonWrite  string
	AuthWrite  string
	AnonDel    string
	AuthDel    string
}

func NewChecker() (*Checker, error) {
	return &Checker{
		ctx:     context.Background(),
		verbose: false,
	}, nil
}

func (c *Checker) SetVerbose(v bool) {
	c.verbose = v
}

func (c *Checker) ListAllBuckets() ([]string, error) {
	// Use AWS CLI to list buckets
	cmd := exec.Command("aws", "s3api", "list-buckets", "--query", "Buckets[].Name", "--output", "text")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error listing buckets: %w", err)
	}

	// Parse output - each bucket name on a new line
	bucketNames := strings.Fields(string(output))
	return bucketNames, nil
}

func (c *Checker) CheckBuckets(bucketNames []string) ([]BucketResult, error) {
	results := make([]BucketResult, 0, len(bucketNames))

	for _, bucketName := range bucketNames {
		result := BucketResult{
			BucketName: bucketName,
		}

		// Check GET-ACL
		result.GetACL = c.checkGetACL(bucketName)

		// Check PUT-ACL
		result.PutACL = c.checkPutACL(bucketName)

		// Check ANON-GET (Anonymous GET)
		result.AnonGet = c.checkAnonGet(bucketName)

		// Check AUTH-GET (Authenticated GET)
		result.AuthGet = c.checkAuthGet(bucketName)

		// Check ANON-WRITE (Anonymous WRITE)
		result.AnonWrite = c.checkAnonWrite(bucketName)

		// Check AUTH-WRITE (Authenticated WRITE)
		result.AuthWrite = c.checkAuthWrite(bucketName)

		// Check ANON-DEL (Anonymous DELETE)
		result.AnonDel = c.checkAnonDel(bucketName)

		// Check AUTH-DEL (Authenticated DELETE)
		result.AuthDel = c.checkAuthDel(bucketName)

		results = append(results, result)
	}

	return results, nil
}

// CheckBucketsStream checks buckets and calls the callback function for each result as it's processed
// All permission checks for a bucket are run in parallel, then waits 1 second before the next bucket
func (c *Checker) CheckBucketsStream(bucketNames []string, callback func(BucketResult)) error {
	for i, bucketName := range bucketNames {
		// Trim whitespace from bucket name
		bucketName = strings.TrimSpace(bucketName)
		if bucketName == "" {
			continue // Skip empty bucket names
		}

		// Create a fresh context for each bucket to avoid cancellation issues
		ctx := context.Background()

		result := BucketResult{
			BucketName: bucketName,
		}

		// Use WaitGroup to wait for all parallel checks to complete
		var wg sync.WaitGroup
		wg.Add(8) // 8 permission checks

		// Use channels to safely collect results from goroutines
		type checkResult struct {
			field string
			value string
		}
		resultsChan := make(chan checkResult, 8)

		// Run all checks in parallel
		go func() {
			defer wg.Done()
			resultsChan <- checkResult{"GetACL", c.checkGetACLWithContext(ctx, bucketName)}
		}()

		go func() {
			defer wg.Done()
			resultsChan <- checkResult{"PutACL", c.checkPutACLWithContext(ctx, bucketName)}
		}()

		go func() {
			defer wg.Done()
			resultsChan <- checkResult{"AnonGet", c.checkAnonGet(bucketName)}
		}()

		go func() {
			defer wg.Done()
			resultsChan <- checkResult{"AuthGet", c.checkAuthGet(bucketName)}
		}()

		go func() {
			defer wg.Done()
			resultsChan <- checkResult{"AnonWrite", c.checkAnonWrite(bucketName)}
		}()

		go func() {
			defer wg.Done()
			resultsChan <- checkResult{"AuthWrite", c.checkAuthWrite(bucketName)}
		}()

		go func() {
			defer wg.Done()
			resultsChan <- checkResult{"AnonDel", c.checkAnonDel(bucketName)}
		}()

		go func() {
			defer wg.Done()
			resultsChan <- checkResult{"AuthDel", c.checkAuthDel(bucketName)}
		}()

		// Wait for all checks to complete and collect results
		go func() {
			wg.Wait()
			close(resultsChan)
		}()

		// Collect all results
		for res := range resultsChan {
			switch res.field {
			case "GetACL":
				result.GetACL = res.value
			case "PutACL":
				result.PutACL = res.value
			case "AnonGet":
				result.AnonGet = res.value
			case "AuthGet":
				result.AuthGet = res.value
			case "AnonWrite":
				result.AnonWrite = res.value
			case "AuthWrite":
				result.AuthWrite = res.value
			case "AnonDel":
				result.AnonDel = res.value
			case "AuthDel":
				result.AuthDel = res.value
			}
		}

		// Call callback immediately with the result
		callback(result)

		// Wait 100ms before processing next bucket (except for the last one)
		if i < len(bucketNames)-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil
}

func (c *Checker) checkGetACL(bucketName string) string {
	return c.checkGetACLWithContext(c.ctx, bucketName)
}

func (c *Checker) checkGetACLWithContext(ctx context.Context, bucketName string) string {
	// Use AWS CLI which handles regions automatically
	cmd := exec.Command("aws", "s3api", "get-bucket-acl", "--bucket", bucketName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[GET-ACL] %s: %v\n", bucketName, string(output))
		}
		errStr := string(output)
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return "DENIED"
		}
		return "DENIED"
	}
	return "OK"
}

func (c *Checker) checkPutACL(bucketName string) string {
	return c.checkPutACLWithContext(c.ctx, bucketName)
}

func (c *Checker) checkPutACLWithContext(ctx context.Context, bucketName string) string {
	// Use AWS CLI: get ACL first, then try to put it back
	// Get ACL
	getCmd := exec.Command("aws", "s3api", "get-bucket-acl", "--bucket", bucketName)
	getOutput, err := getCmd.CombinedOutput()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[PUT-ACL] %s (get): %v\n", bucketName, string(getOutput))
		}
		errStr := string(getOutput)
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return "DENIED"
		}
		return "DENIED"
	}

	// Save ACL to temp file
	tmpFile := fmt.Sprintf("/tmp/acl-%s-%d.json", bucketName, time.Now().UnixNano())
	err = os.WriteFile(tmpFile, getOutput, 0644)
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[PUT-ACL] %s (write temp): %v\n", bucketName, err)
		}
		return "DENIED"
	}
	defer os.Remove(tmpFile)

	// Try to put ACL back (no-op change)
	putCmd := exec.Command("aws", "s3api", "put-bucket-acl", "--bucket", bucketName, "--access-control-policy", "file://"+tmpFile)
	putOutput, err := putCmd.CombinedOutput()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[PUT-ACL] %s (put): %v\n", bucketName, string(putOutput))
		}
		errStr := string(putOutput)
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return "DENIED"
		}
		return "DENIED"
	}
	return "OK"
}

func (c *Checker) checkAnonGet(bucketName string) string {
	// Check bucket policy and public access block settings
	// Then try to access with anonymous credentials
	testKey := fmt.Sprintf("test-%d", time.Now().UnixNano())

	// Check public access block using AWS CLI
	pabCmd := exec.Command("aws", "s3api", "get-public-access-block", "--bucket", bucketName)
	pabOutput, pabErr := pabCmd.CombinedOutput()
	if pabErr != nil {
		// Error might mean no PAB is configured (which is OK)
		errStr := string(pabOutput)
		if c.verbose && !strings.Contains(errStr, "NoSuchPublicAccessBlockConfiguration") {
			fmt.Fprintf(os.Stderr, "[ANON-GET] %s (public-access-block): %v\n", bucketName, errStr)
		}
	} else {
		// Parse JSON output to check if public access is blocked
		pabStr := string(pabOutput)
		if strings.Contains(pabStr, `"BlockPublicAcls": true`) ||
			strings.Contains(pabStr, `"BlockPublicPolicy": true`) ||
			strings.Contains(pabStr, `"IgnorePublicAcls": true`) ||
			strings.Contains(pabStr, `"RestrictPublicBuckets": true`) {
			return "DENIED"
		}
	}
	// If GetPublicAccessBlock returned an error, it might mean no PAB is configured (which is OK)
	// or we don't have permission to check it (which we'll discover when trying anonymous access)

	// Use AWS CLI with --no-sign-request for anonymous access
	cmd := exec.Command("aws", "s3api", "head-object", "--bucket", bucketName, "--key", testKey, "--no-sign-request")
	output, err := cmd.CombinedOutput()
	if err != nil {
		errStr := string(output)
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[ANON-GET] %s: %v\n", bucketName, errStr)
		}
		if strings.Contains(errStr, "NoSuchKey") || strings.Contains(errStr, "404") {
			return "OK" // Anonymous access is allowed, just key doesn't exist
		}
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return "DENIED"
		}
		// For other errors, try checking bucket policy as fallback
		return c.checkBucketPolicyForAnonGet(bucketName)
	}
	return "OK"
}

func (c *Checker) checkBucketPolicyForAnonGet(bucketName string) string {
	// Check bucket policy for public read access using AWS CLI
	cmd := exec.Command("aws", "s3api", "get-bucket-policy", "--bucket", bucketName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[ANON-GET] %s (policy): %v\n", bucketName, string(output))
		}
		// If we can't get the policy, we can't determine anonymous access from policy
		// Return DENIED as conservative default
		return "DENIED"
	}

	// Parse JSON output - extract Policy field
	policyStr := string(output)
	// Simple check: if policy contains "Principal": "*", it might allow anonymous access
	if strings.Contains(policyStr, `"Principal":"*"`) || strings.Contains(policyStr, `"Principal":{"AWS":"*"}`) {
		if strings.Contains(policyStr, `"s3:GetObject"`) || strings.Contains(policyStr, `"s3:Get*"`) {
			return "OK"
		}
	}
	// Policy exists but doesn't allow anonymous access
	return "DENIED"
}

func (c *Checker) checkAuthGet(bucketName string) string {
	// Use AWS CLI: try to head a non-existent object
	// 404/NoSuchKey = access allowed, 403 = denied
	testKey := fmt.Sprintf("test-%d", time.Now().UnixNano())
	cmd := exec.Command("aws", "s3api", "head-object", "--bucket", bucketName, "--key", testKey)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errStr := string(output)
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[AUTH-GET] %s: %v\n", bucketName, errStr)
		}
		if strings.Contains(errStr, "NoSuchKey") || strings.Contains(errStr, "404") {
			return "OK" // Access allowed, just key doesn't exist
		}
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return "DENIED"
		}
		return "DENIED"
	}
	return "OK"
}

func (c *Checker) checkAnonWrite(bucketName string) string {
	// Check public access block using AWS CLI
	pabCmd := exec.Command("aws", "s3api", "get-public-access-block", "--bucket", bucketName)
	pabOutput, pabErr := pabCmd.CombinedOutput()
	if pabErr != nil {
		// Error might mean no PAB is configured (which is OK)
		errStr := string(pabOutput)
		if c.verbose && !strings.Contains(errStr, "NoSuchPublicAccessBlockConfiguration") {
			fmt.Fprintf(os.Stderr, "[ANON-WRITE] %s (public-access-block): %v\n", bucketName, errStr)
		}
	} else {
		// Parse JSON output to check if public access is blocked
		pabStr := string(pabOutput)
		if strings.Contains(pabStr, `"BlockPublicAcls": true`) ||
			strings.Contains(pabStr, `"BlockPublicPolicy": true`) ||
			strings.Contains(pabStr, `"IgnorePublicAcls": true`) ||
			strings.Contains(pabStr, `"RestrictPublicBuckets": true`) {
			return "DENIED"
		}
	}

	// Use AWS CLI with --no-sign-request for anonymous write
	testKey := fmt.Sprintf("test-anon-write-%d", time.Now().UnixNano())
	tmpFile := fmt.Sprintf("/tmp/test-%s-%d", bucketName, time.Now().UnixNano())
	err := os.WriteFile(tmpFile, []byte("test"), 0644)
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[ANON-WRITE] %s (write temp): %v\n", bucketName, err)
		}
		return "DENIED"
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("aws", "s3api", "put-object", "--bucket", bucketName, "--key", testKey, "--body", tmpFile, "--no-sign-request")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[ANON-WRITE] %s: %v\n", bucketName, string(output))
		}
		errStr := string(output)
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return "DENIED"
		}
		return "DENIED"
	}

	// Clean up the test object
	delCmd := exec.Command("aws", "s3api", "delete-object", "--bucket", bucketName, "--key", testKey, "--no-sign-request")
	delCmd.Run() // Ignore cleanup errors

	return "OK"
}

func (c *Checker) checkAuthWrite(bucketName string) string {
	// Use AWS CLI: try to put an object
	testKey := fmt.Sprintf("test-auth-write-%d", time.Now().UnixNano())
	tmpFile := fmt.Sprintf("/tmp/test-%s-%d", bucketName, time.Now().UnixNano())
	err := os.WriteFile(tmpFile, []byte("test"), 0644)
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[AUTH-WRITE] %s (write temp): %v\n", bucketName, err)
		}
		return "DENIED"
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("aws", "s3api", "put-object", "--bucket", bucketName, "--key", testKey, "--body", tmpFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[AUTH-WRITE] %s (put): %v\n", bucketName, string(output))
		}
		errStr := string(output)
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return "DENIED"
		}
		return "DENIED"
	}

	// Clean up the test object
	delCmd := exec.Command("aws", "s3api", "delete-object", "--bucket", bucketName, "--key", testKey)
	delCmd.Run() // Ignore cleanup errors

	return "OK"
}

func (c *Checker) checkAnonDel(bucketName string) string {
	// Check public access block using AWS CLI
	pabCmd := exec.Command("aws", "s3api", "get-public-access-block", "--bucket", bucketName)
	pabOutput, pabErr := pabCmd.CombinedOutput()
	if pabErr != nil {
		// Error might mean no PAB is configured (which is OK)
		errStr := string(pabOutput)
		if c.verbose && !strings.Contains(errStr, "NoSuchPublicAccessBlockConfiguration") {
			fmt.Fprintf(os.Stderr, "[ANON-DEL] %s (public-access-block): %v\n", bucketName, errStr)
		}
	} else {
		// Parse JSON output to check if public access is blocked
		pabStr := string(pabOutput)
		if strings.Contains(pabStr, `"BlockPublicAcls": true`) ||
			strings.Contains(pabStr, `"BlockPublicPolicy": true`) ||
			strings.Contains(pabStr, `"IgnorePublicAcls": true`) ||
			strings.Contains(pabStr, `"RestrictPublicBuckets": true`) {
			return "DENIED"
		}
	}

	// First create a test object with authenticated client (using AWS CLI)
	testKey := fmt.Sprintf("test-anon-del-%d", time.Now().UnixNano())
	tmpFile := fmt.Sprintf("/tmp/test-%s-%d", bucketName, time.Now().UnixNano())
	err := os.WriteFile(tmpFile, []byte("test"), 0644)
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[ANON-DEL] %s (write temp): %v\n", bucketName, err)
		}
		return "DENIED"
	}
	defer os.Remove(tmpFile)

	putCmd := exec.Command("aws", "s3api", "put-object", "--bucket", bucketName, "--key", testKey, "--body", tmpFile)
	putOutput, err := putCmd.CombinedOutput()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[ANON-DEL] %s (create test object): %v\n", bucketName, string(putOutput))
		}
		return "DENIED"
	}

	// Now try to delete it with anonymous credentials (using AWS CLI with --no-sign-request)
	delCmd := exec.Command("aws", "s3api", "delete-object", "--bucket", bucketName, "--key", testKey, "--no-sign-request")
	delOutput, err := delCmd.CombinedOutput()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[ANON-DEL] %s: %v\n", bucketName, string(delOutput))
		}
		// Clean up with authenticated client
		cleanupCmd := exec.Command("aws", "s3api", "delete-object", "--bucket", bucketName, "--key", testKey)
		cleanupCmd.Run()
		errStr := string(delOutput)
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return "DENIED"
		}
		return "DENIED"
	}

	return "OK"
}

func (c *Checker) checkAuthDel(bucketName string) string {
	// Use AWS CLI: create test object, then try to delete it
	testKey := fmt.Sprintf("test-auth-del-%d", time.Now().UnixNano())
	tmpFile := fmt.Sprintf("/tmp/test-%s-%d", bucketName, time.Now().UnixNano())
	err := os.WriteFile(tmpFile, []byte("test"), 0644)
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[AUTH-DEL] %s (write temp): %v\n", bucketName, err)
		}
		return "DENIED"
	}
	defer os.Remove(tmpFile)

	// Create test object
	putCmd := exec.Command("aws", "s3api", "put-object", "--bucket", bucketName, "--key", testKey, "--body", tmpFile)
	putOutput, err := putCmd.CombinedOutput()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[AUTH-DEL] %s (put): %v\n", bucketName, string(putOutput))
		}
		errStr := string(putOutput)
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return "DENIED"
		}
		return "DENIED"
	}

	// Try to delete it
	delCmd := exec.Command("aws", "s3api", "delete-object", "--bucket", bucketName, "--key", testKey)
	delOutput, err := delCmd.CombinedOutput()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[AUTH-DEL] %s (delete): %v\n", bucketName, string(delOutput))
		}
		errStr := string(delOutput)
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return "DENIED"
		}
		return "DENIED"
	}

	return "OK"
}
