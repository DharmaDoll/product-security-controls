# INSECURE TEST FIXTURE ONLY. Never apply this configuration.
resource "aws_s3_bucket" "public_fixture" {
  bucket = "psb-insecure-fixture-never-deploy"
}

resource "aws_s3_bucket_public_access_block" "public_fixture" {
  bucket                  = aws_s3_bucket.public_fixture.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
