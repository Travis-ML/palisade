resource "aws_s3_bucket" "ledger" {
  bucket              = "palisade-ledger-prod"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "ledger" {
  bucket = aws_s3_bucket.ledger.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "ledger" {
  bucket = aws_s3_bucket.ledger.id
  rule {
    default_retention {
      mode = "COMPLIANCE"   # not GOVERNANCE: no privileged bypass
      days = 400
    }
  }
}
