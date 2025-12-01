# Crypto Library

Client-side cryptographic operations using Web Crypto API.

## Files (To be created)

- `keyGeneration.ts` - RSA/ECC key pair generation
- `encryption.ts` - AES-256-GCM encryption
- `decryption.ts` - AES-256-GCM decryption
- `keyExchange.ts` - ECDH key exchange protocol
- `signatures.ts` - Digital signature generation and verification
- `storage.ts` - Secure key storage in IndexedDB

## Critical Requirements

- All crypto operations MUST be client-side only
- Private keys NEVER leave the client
- Use only Web Crypto API (SubtleCrypto)
- AES-256-GCM with fresh IV per message
- RSA ≥ 2048 bits or ECC P-256/P-384
