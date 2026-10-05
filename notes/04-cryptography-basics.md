# 04 — Cryptography Basics

## Symmetric vs asymmetric

| | Symmetric | Asymmetric |
|---|---|---|
| Keys | One shared secret | Public / private key pair |
| Speed | Fast (bulk data) | Slow (key exchange, signatures) |
| Examples | AES-256-GCM, ChaCha20-Poly1305 | RSA-3072, ECDSA / Ed25519, ECDH |
| Problem | Key distribution | Trusting the public key → PKI / certificates |

**Hybrid encryption** (TLS) uses asymmetric crypto (ECDHE) to agree on a session key, then symmetric AES-GCM for the data.

## Hashing

- One-way and fixed-length: SHA-256, SHA-3. **MD5 and SHA-1 are broken** for collision resistance.
- Used for integrity checks, digital signatures, and file fingerprints.
- **Passwords need slow, salted hashes**: bcrypt, scrypt, Argon2id, PBKDF2 (≥ 600,000 iterations for SHA-256 per OWASP 2023). Never use plain SHA-256.
- **HMAC** = hash + secret key, which gives message authentication (API signatures, JWT HS256).

## Digital signatures and certificates

```
Sign:   signature = Sign(private_key, hash(message))
Verify: Verify(public_key, signature, hash(message)) → valid / invalid
```

An X.509 certificate binds a public key to an identity and is signed by a Certificate Authority. The browser trusts it through the chain leaf → intermediate → root.

## TLS 1.3 handshake (simplified)

1. ClientHello: supported ciphers + key share (ECDHE)
2. ServerHello: chosen cipher + key share, then the encrypted certificate and Finished
3. Both derive the session keys and application data flows, after **1 round trip** (0-RTT optional)

## Password entropy

`entropy = length × log2(charset size)`. Twelve random characters from 94 printable symbols gives about 79 bits. Use [`tools/password_audit.py`](../tools/password_audit.py) to estimate entropy and detect weak patterns.
