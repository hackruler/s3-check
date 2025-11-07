# S3 Permission Checks - AWS API Calls

This document explains what AWS API calls are made for each permission check.

## GET-ACL
**AWS API Call:** `GetBucketAcl`
- Checks if the authenticated user can read the bucket's Access Control List (ACL)
- **Command equivalent:** `aws s3api get-bucket-acl --bucket <bucket-name>`

## PUT-ACL
**AWS API Calls:** `GetBucketAcl` + `PutBucketAcl`
- First gets the current ACL, then tries to put it back (no-op change)
- Checks if the authenticated user can modify the bucket's ACL
- **Command equivalent:** 
  ```bash
  aws s3api get-bucket-acl --bucket <bucket-name>
  aws s3api put-bucket-acl --bucket <bucket-name> --access-control-policy <current-acl>
  ```

## ANON-GET (Anonymous GET)
**AWS API Calls:** `GetPublicAccessBlock` + `HeadObject` (with anonymous credentials)
- Checks if anonymous (unauthenticated) users can read objects
- First checks public access block settings
- Then tries to access an object using anonymous credentials
- If that fails, checks bucket policy for public read access
- **Command equivalent:**
  ```bash
  aws s3api get-public-access-block --bucket <bucket-name>
  # Then with anonymous credentials (no AWS credentials):
  aws s3api head-object --bucket <bucket-name> --key <test-key> --no-sign-request
  ```

## AUTH-GET (Authenticated GET)
**AWS API Call:** `HeadObject`
- Checks if authenticated user can read objects
- **Command equivalent:** `aws s3api head-object --bucket <bucket-name> --key <test-key>`

## ANON-WRITE (Anonymous WRITE)
**AWS API Calls:** `GetPublicAccessBlock` + `PutObject` (with anonymous credentials) + `DeleteObject`
- Checks if anonymous users can write objects
- First checks public access block settings
- Then tries to PUT an object using anonymous credentials
- Cleans up the test object after
- **Command equivalent:**
  ```bash
  aws s3api get-public-access-block --bucket <bucket-name>
  # Then with anonymous credentials:
  aws s3api put-object --bucket <bucket-name> --key <test-key> --body <test-file> --no-sign-request
  aws s3api delete-object --bucket <bucket-name> --key <test-key> --no-sign-request
  ```

## AUTH-WRITE (Authenticated WRITE)
**AWS API Calls:** `PutObject` + `DeleteObject`
- Checks if authenticated user can write objects
- Creates a test object, then deletes it
- **Command equivalent:**
  ```bash
  aws s3api put-object --bucket <bucket-name> --key <test-key> --body <test-file>
  aws s3api delete-object --bucket <bucket-name> --key <test-key>
  ```

## ANON-DEL (Anonymous DELETE)
**AWS API Calls:** `GetPublicAccessBlock` + `PutObject` (authenticated) + `DeleteObject` (anonymous)
- Checks if anonymous users can delete objects
- First creates a test object with authenticated credentials
- Then tries to delete it with anonymous credentials
- **Command equivalent:**
  ```bash
  aws s3api get-public-access-block --bucket <bucket-name>
  aws s3api put-object --bucket <bucket-name> --key <test-key> --body <test-file>
  # Then with anonymous credentials:
  aws s3api delete-object --bucket <bucket-name> --key <test-key> --no-sign-request
  ```

## AUTH-DEL (Authenticated DELETE)
**AWS API Calls:** `PutObject` + `DeleteObject`
- Checks if authenticated user can delete objects
- Creates a test object, then deletes it
- **Command equivalent:**
  ```bash
  aws s3api put-object --bucket <bucket-name> --key <test-key> --body <test-file>
  aws s3api delete-object --bucket <bucket-name> --key <test-key>
  ```

## Notes

- All checks use the AWS SDK for Go v2
- Test objects are created with unique keys using timestamps to avoid conflicts
- Test objects are cleaned up after checks (except when checks fail early)
- Anonymous checks use `aws.AnonymousCredentials{}` which provides no authentication
- The tool checks permissions by actually attempting operations, not just reading policies

