package checker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	// Delay between bucket checks to avoid rate limiting
	bucketCheckDelay = 100 * time.Millisecond
)

type Checker struct {
	client      *s3.Client
	ctx         context.Context
	verbose     bool
	regionCache map[string]string // Cache bucket -> region mapping
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
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg)
	return &Checker{
		client:      client,
		ctx:         context.Background(),
		verbose:     false,
		regionCache: make(map[string]string),
	}, nil
}

func (c *Checker) SetVerbose(v bool) {
	c.verbose = v
}

func (c *Checker) ListAllBuckets() ([]string, error) {
	result, err := c.client.ListBuckets(c.ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	buckets := make([]string, 0, len(result.Buckets))
	for _, bucket := range result.Buckets {
		buckets = append(buckets, *bucket.Name)
	}
	return buckets, nil
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
func (c *Checker) CheckBucketsStream(bucketNames []string, callback func(BucketResult)) error {
	for _, bucketName := range bucketNames {
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

		// Check GET-ACL
		result.GetACL = c.checkGetACLWithContext(ctx, bucketName)

		// Check PUT-ACL
		result.PutACL = c.checkPutACLWithContext(ctx, bucketName)

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

		// Call callback immediately with the result
		callback(result)
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

	// Check public access block
	pab, err := c.client.GetPublicAccessBlock(c.ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil && c.verbose {
		// Log error but continue - error might mean no PAB is configured
		errStr := err.Error()
		if !strings.Contains(errStr, "NoSuchPublicAccessBlockConfiguration") {
			fmt.Fprintf(os.Stderr, "[ANON-GET] %s (public-access-block): %v\n", bucketName, err)
		}
	}
	if err == nil && pab.PublicAccessBlockConfiguration != nil {
		// If public access is blocked, anonymous access is denied
		if pab.PublicAccessBlockConfiguration.BlockPublicAcls != nil && *pab.PublicAccessBlockConfiguration.BlockPublicAcls {
			return "DENIED"
		}
		if pab.PublicAccessBlockConfiguration.BlockPublicPolicy != nil && *pab.PublicAccessBlockConfiguration.BlockPublicPolicy {
			return "DENIED"
		}
		if pab.PublicAccessBlockConfiguration.IgnorePublicAcls != nil && *pab.PublicAccessBlockConfiguration.IgnorePublicAcls {
			return "DENIED"
		}
		if pab.PublicAccessBlockConfiguration.RestrictPublicBuckets != nil && *pab.PublicAccessBlockConfiguration.RestrictPublicBuckets {
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
	// Check bucket policy for public read access
	policy, err := c.client.GetBucketPolicy(c.ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		if c.verbose {
			fmt.Fprintf(os.Stderr, "[ANON-GET] %s (policy): %v\n", bucketName, err)
		}
		// If we can't get the policy, we can't determine anonymous access from policy
		// Return DENIED as conservative default
		return "DENIED"
	}

	// Simple check: if policy exists and contains "Principal": "*", it might allow anonymous access
	// This is a simplified check - full policy parsing would be more accurate
	policyStr := *policy.Policy
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
	// Check public access block first
	pab, err := c.client.GetPublicAccessBlock(c.ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil && c.verbose {
		errStr := err.Error()
		if !strings.Contains(errStr, "NoSuchPublicAccessBlockConfiguration") {
			fmt.Fprintf(os.Stderr, "[ANON-WRITE] %s (public-access-block): %v\n", bucketName, err)
		}
	}
	if err == nil && pab.PublicAccessBlockConfiguration != nil {
		if pab.PublicAccessBlockConfiguration.BlockPublicAcls != nil && *pab.PublicAccessBlockConfiguration.BlockPublicAcls {
			return "DENIED"
		}
		if pab.PublicAccessBlockConfiguration.BlockPublicPolicy != nil && *pab.PublicAccessBlockConfiguration.BlockPublicPolicy {
			return "DENIED"
		}
		if pab.PublicAccessBlockConfiguration.IgnorePublicAcls != nil && *pab.PublicAccessBlockConfiguration.IgnorePublicAcls {
			return "DENIED"
		}
		if pab.PublicAccessBlockConfiguration.RestrictPublicBuckets != nil && *pab.PublicAccessBlockConfiguration.RestrictPublicBuckets {
			return "DENIED"
		}
	}

	// Use AWS CLI with --no-sign-request for anonymous write
	testKey := fmt.Sprintf("test-anon-write-%d", time.Now().UnixNano())
	tmpFile := fmt.Sprintf("/tmp/test-%s-%d", bucketName, time.Now().UnixNano())
	err = os.WriteFile(tmpFile, []byte("test"), 0644)
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
	// Check public access block first
	pab, err := c.client.GetPublicAccessBlock(c.ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil && c.verbose {
		errStr := err.Error()
		if !strings.Contains(errStr, "NoSuchPublicAccessBlockConfiguration") {
			fmt.Fprintf(os.Stderr, "[ANON-DEL] %s (public-access-block): %v\n", bucketName, err)
		}
	}
	if err == nil && pab.PublicAccessBlockConfiguration != nil {
		if pab.PublicAccessBlockConfiguration.BlockPublicAcls != nil && *pab.PublicAccessBlockConfiguration.BlockPublicAcls {
			return "DENIED"
		}
		if pab.PublicAccessBlockConfiguration.BlockPublicPolicy != nil && *pab.PublicAccessBlockConfiguration.BlockPublicPolicy {
			return "DENIED"
		}
		if pab.PublicAccessBlockConfiguration.IgnorePublicAcls != nil && *pab.PublicAccessBlockConfiguration.IgnorePublicAcls {
			return "DENIED"
		}
		if pab.PublicAccessBlockConfiguration.RestrictPublicBuckets != nil && *pab.PublicAccessBlockConfiguration.RestrictPublicBuckets {
			return "DENIED"
		}
	}

	// First create a test object with authenticated client (using AWS CLI)
	testKey := fmt.Sprintf("test-anon-del-%d", time.Now().UnixNano())
	tmpFile := fmt.Sprintf("/tmp/test-%s-%d", bucketName, time.Now().UnixNano())
	err = os.WriteFile(tmpFile, []byte("test"), 0644)
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
