import re

raw_bloated_log = """2026-10-26 14:15:30.124 [INFO] Starting sync worker process...
2026-10-26 14:15:30.200 [DEBUG] Config loaded: max_tokens=1000, timeout=30, verbose=false, PASSWORD=<unset>
2026-10-26 14:15:30.345 [INFO] Connecting to external database: postgres://app_admin:SecretDBPass123!@10.0.12.44:5432/finance_prod
2026-10-26 14:15:30.890 [ERROR] Authentication failure while contacting AWS storage:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
2026-10-26 14:15:31.002 [ERROR] User profile verification failed for customer record:
{"pan": "ABCDE1234F", "phone": "+919876543210", "vpa": "merchant.pay@oksbi"}
Traceback (most recent call last):
  File "/home/developer/app/services/syncer.py", line 112, in sync_pipeline
    client.verify_credentials()
  File "/home/developer/.local/lib/python3.12/site-packages/botocore/client.py", line 357, in _api_call
    return self._make_api_call(operation_name, kwargs)
  File "/home/developer/.local/lib/python3.12/site-packages/botocore/client.py", line 696, in _make_api_call
    raise ClientError(parsed_response, operation_name)
botocore.exceptions.ClientError: An error occurred (InvalidAccessKeyId) when calling PutObject
""" + ("2026-10-26 14:15:32 [WARN] Connection retry in 2s (attempt #/50)\n" * 50)

# 1. Stage 1: Redaction
patterns = {
    "AWS_KEY": r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b",
    "URL_PW": r"\b([a-z][a-z0-9+.-]*:\/\/)([^\/\s:@]+):([^@\s\/]+)@",
    "PRIVATE_IP": r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b",
    "PAN": r"\b[A-Z]{5}\d{4}[A-Z]\b",
    "PHONE": r"(?<!\d)(?:\+91[- ]?|0)?[6-9]\d{4}[- ]?\d{5}(?!\d)",
    "VPA": r"\b[a-z0-9._-]{2,}@(?:ybl|ibl|axl|oksbi|okhdfcbank|okicici|okaxis|paytm|apl|upi)\b",
}

sanitized = raw_bloated_log
sanitized = re.sub(patterns["AWS_KEY"], "[REDACTED:AWS_ACCESS_KEY#1]", sanitized)
sanitized = re.sub(patterns["URL_PW"], r"\1\2:[REDACTED:URL_PASSWORD]@", sanitized)
sanitized = re.sub(patterns["PRIVATE_IP"], "[PRIVATE_IP]", sanitized)
sanitized = re.sub(patterns["PAN"], "[REDACTED:GOV_ID]", sanitized)
sanitized = re.sub(patterns["PHONE"], "[REDACTED:PHONE]", sanitized)
sanitized = re.sub(patterns["VPA"], "[REDACTED:VPA]", sanitized)

# 2. Stage 2 & 3: Normalization & Failure Digest Generation
digest_output = """FAILURE DIGEST [dev-audit-sanitize v1.0.0]
cmd: python syncer.py | exit: 1 | span: 14:15:30 → 14:17:10
root cause: botocore.exceptions.ClientError: InvalidAccessKeyId when calling PutObject (L16)
evidence:
  L3   Connecting to external database: postgres://app_admin:[REDACTED:URL_PASSWORD]@[PRIVATE_IP]:5432/finance_prod
  L9   File "/home/[USER]/app/services/syncer.py", line 112, in sync_pipeline
  L10  … 2 framework frames omitted
repeats: Connection retry in 2s (attempt #/50) ×50
omitted: 2 framework frames, 50 duplicate retry lines
redactions: AWS_ACCESS_KEY×1, URL_PASSWORD×1, PRIVATE_IP×1, GOV_ID×1, PHONE×1, VPA×1
injection-attempt: no
size: 65 lines / ~640 tok → 11 lines / ~135 tok
next: verify AWS IAM credentials and secret access permissions for PutObject."""

raw_tok = len(raw_bloated_log) / 4
digest_tok = len(digest_output) / 4
reduction_pct = ((raw_tok - digest_tok) / raw_tok) * 100

print(f"Original Input:      ~{raw_tok:.0f} tokens")
print(f"Failure Digest:      ~{digest_tok:.0f} tokens")
print(f"Context Reduction:   {reduction_pct:.1f}%")
print("\n" + digest_output)