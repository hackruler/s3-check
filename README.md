# s3-check

A tool to check various S3 bucket permissions including GET-ACL, PUT-ACL, GET, WRITE, and DELETE operations for both authenticated and unauthenticated users.

## Installation

```bash
go build -o s3-check .
```

Or install globally:

```bash
go install
```

## Usage

Check permissions for S3 buckets. Buckets can be specified in multiple ways:

1. **As command line arguments:**
   ```bash
   ./s3-check check bucket1 bucket2
   ```

2. **From a file:**
   ```bash
   ./s3-check check --file buckets.txt
   ```

3. **From stdin:**
   ```bash
   echo "bucket1" | ./s3-check check --stdin
   ```

4. **All buckets** (requires AWS permissions to list all buckets):
   ```bash
   ./s3-check check
   ```

## Output

The tool outputs a table showing the permission status for each bucket:

```
BUCKET                    | GET-ACL  | PUT-ACL  | ANON-GET  | AUTH-GET  | ANON-WRITE | AUTH-WRITE | ANON-DEL  | AUTH-DEL 
--------------------------+----------+----------+-----------+-----------+------------+------------+-----------+----------
test-bucket-123           | DENIED   | DENIED   | DENIED    | DENIED    | OK         | OK         | DENIED    | DENIED   

Legend:
  ANON - Anonymous (unauthenticated) access
  AUTH - Authenticated access
```

## Permissions Checked

- **GET-ACL**: Ability to read bucket ACL
- **PUT-ACL**: Ability to modify bucket ACL
- **ANON-GET**: Anonymous (unauthenticated) read access
- **AUTH-GET**: Authenticated read access
- **ANON-WRITE**: Anonymous (unauthenticated) write access
- **AUTH-WRITE**: Authenticated write access
- **ANON-DEL**: Anonymous (unauthenticated) delete access
- **AUTH-DEL**: Authenticated delete access

## Requirements

- Go 1.21 or later
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)
- Appropriate AWS permissions to check bucket permissions

