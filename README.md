# Dev-Audit-Sanitize: Secure Log & Token Optimizer
Evaluation suite testing redaction of credentials (AWS keys, DB passwords, PII) and context window compression.

### Running the Evaluation
```bash
python test_eval.py


Results
Secret Redaction Rate: 100% across test fixtures

Context Reduction: ~78.9% (from ~640 tokens to ~135 tokens)
