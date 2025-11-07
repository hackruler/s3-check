# AWS CLI Commands to Check S3 Bucket Permissions

## Write Permissions

### Check Authenticated Write (AUTH-WRITE)
```bash
# Try to upload a test object
aws s3api put-object --bucket cowplat --key test-write-$(date +%s) --body /dev/stdin <<< "test"
```

### Check Anonymous Write (ANON-WRITE)
```bash
# First check public access block settings
aws s3api get-public-access-block --bucket cowplat

# Check bucket policy for public write access
aws s3api get-bucket-policy --bucket cowplat

# Try anonymous write (requires setting up anonymous credentials)
# This is complex - the tool handles it automatically
```

## Read Permissions

### Check Authenticated Read (AUTH-GET)
```bash
# Try to head a non-existent object (404 = access allowed, 403 = denied)
aws s3api head-object --bucket cowplat --key test-nonexistent-$(date +%s)
```

### Check Anonymous Read (ANON-GET)
```bash
# Check public access block
aws s3api get-public-access-block --bucket cowplat

# Check bucket policy
aws s3api get-bucket-policy --bucket cowplat

# Try anonymous read (requires anonymous credentials setup)
```

## ACL Permissions

### Check Get ACL (GET-ACL)
```bash
aws s3api get-bucket-acl --bucket cowplat
```

### Check Put ACL (PUT-ACL)
```bash
# Get current ACL
aws s3api get-bucket-acl --bucket cowplat > acl.json

# Try to put it back (no-op change)
aws s3api put-bucket-acl --bucket cowplat --access-control-policy file://acl.json
```

## Delete Permissions

### Check Authenticated Delete (AUTH-DEL)
```bash
# Create test object
TEST_KEY="test-delete-$(date +%s)"
aws s3api put-object --bucket cowplat --key $TEST_KEY --body /dev/stdin <<< "test"

# Try to delete it
aws s3api delete-object --bucket cowplat --key $TEST_KEY
```

### Check Anonymous Delete (ANON-DEL)
```bash
# Check public access block first
aws s3api get-public-access-block --bucket cowplat

# Then try anonymous delete (requires anonymous credentials)
```

## Complete Check Script

```bash
#!/bin/bash
BUCKET="cowplat"

echo "=== Checking $BUCKET permissions ==="

echo -n "GET-ACL: "
aws s3api get-bucket-acl --bucket $BUCKET > /dev/null 2>&1 && echo "OK" || echo "DENIED"

echo -n "PUT-ACL: "
aws s3api get-bucket-acl --bucket $BUCKET > /tmp/acl.json 2>&1
if [ $? -eq 0 ]; then
  aws s3api put-bucket-acl --bucket $BUCKET --access-control-policy file:///tmp/acl.json > /dev/null 2>&1 && echo "OK" || echo "DENIED"
else
  echo "DENIED"
fi

echo -n "AUTH-GET: "
aws s3api head-object --bucket $BUCKET --key test-$(date +%s) 2>&1 | grep -q "404\|NoSuchKey" && echo "OK" || echo "DENIED"

echo -n "AUTH-WRITE: "
TEST_KEY="test-write-$(date +%s)"
aws s3api put-object --bucket $BUCKET --key $TEST_KEY --body /dev/stdin <<< "test" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  aws s3api delete-object --bucket $BUCKET --key $TEST_KEY > /dev/null 2>&1
  echo "OK"
else
  echo "DENIED"
fi

echo -n "AUTH-DEL: "
TEST_KEY="test-del-$(date +%s)"
aws s3api put-object --bucket $BUCKET --key $TEST_KEY --body /dev/stdin <<< "test" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  aws s3api delete-object --bucket $BUCKET --key $TEST_KEY > /dev/null 2>&1 && echo "OK" || echo "DENIED"
else
  echo "DENIED"
fi
```

## Note on Region Issues

If you get `PermanentRedirect` errors, specify the region:

```bash
aws s3api put-object --bucket cowplat --key test --body /dev/stdin <<< "test" --region us-west-2
```

To find the bucket's region:
```bash
aws s3api get-bucket-location --bucket cowplat
```

