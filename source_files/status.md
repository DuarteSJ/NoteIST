# Security Enhancement Proposal

## Authentication Mechanism: Private Key Generation . I am doing this - Duarte

### Key Generation Process
- Private key derived dynamically using:
  - Randomly generated local salt
  - User-provided passphrase
- Key generation steps:
  1. Generate random salt (stored locally)
  2. Combine salt with user passphrase
  3. Derive private key from this combination
  4. Do NOT store the private key persistently

### Authentication Advantages
- No static private key storage
- Protection against local attack vectors
- Dynamic key generation per session
- User must know passphrase to regenerate key

## Document Encryption Strategy

### Previous Approach
- Entire JSON file encrypted as a single unit

### New Selective Encryption
```json
{
    "id": 12,
    "title": "encrypted-title",
    "content": "encrypted-content",
    "hmac": "hmac(title+content)",
    "version": 2
}
```

### Key Encryption Changes
- Encrypt only `title` and `content`
- HMAC generated from encrypted fields
- `id` remains unencrypted
- More granular encryption model

## Security Implications
- Reduced attack surface
- More flexible encryption strategy
- Performance optimization
- Enhanced key management


# TODO: adicionar o que falta fazer