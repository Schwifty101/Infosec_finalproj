# Database Library

MongoDB connection and utilities.

## Files (To be created)

- `connection.ts` - MongoDB connection handler
- `models.ts` - Database schemas and models

## Critical Requirements

- Store ONLY encrypted data (ciphertext, IV, metadata)
- NEVER store plaintext messages or private keys
- All server-side code is for storage/retrieval only
- No decryption operations on server
