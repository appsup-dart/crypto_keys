[![pub package](https://img.shields.io/pub/v/crypto_keys.svg)](https://pub.dev/packages/crypto_keys)
[![Build Status](https://travis-ci.org/appsup-dart/crypto_keys.svg?branch=master)](https://travis-ci.org/appsup-dart/crypto_keys)
[:heart: sponsor](https://github.com/sponsors/rbellens)

**crypto_keys** exposes the most common cryptographic operations—signing, symmetric and RSA encryption, key agreement, password and shared-secret key derivation—in a **single unified, easy-to-use, ergonomic API**. You combine **`algorithms.*`** from **`package:crypto_keys/catalog.dart`** with concrete **keys** and secret material (`SymmetricKey`, `Rsa*`, `Ec*`, `Edwards*`, `Montgomery*`, `Password`, `SecretBytes`) using **key-first** or **algorithm-first** styles ([**Using the API**](#using-the-api)).

---

## Contents

1. [Signing and verifying](#signing-and-verifying)  
2. [Encryption and decryption](#encryption-and-decryption)  
3. [Key agreement](#key-agreement)  
4. [Key derivation](#key-derivation)  
5. [Digests (hashes)](#digests-hashes)  
6. [Key types and materials](#key-types-and-materials)  
7. [Key generation and importing](#key-generation-and-importing)  
8. [Using the API](#using-the-api) — [catalog](#the-catalog); key-first vs algorithm-first; dot shorthand  
9. [Example programs](#bundled-example-programs) · [Implementation](#implementation) · [Bugs](#features-and-bugs) · [Sponsor](#sponsor)

---

## Signing and verifying

**What it is for:** Signing answers whether someone with the **right secret capability** approved **exactly these message bytes**. You get **integrity** (tampering breaks verification) and, under your trust model, **authenticity**. It does **not** hide the message—that is encryption.

**Example (easy mental model):** Alice sends a message to Bob. Bob wants to be sure it really came from Alice and was not modified. Alice **signs** with her **private** signing key; Bob **verifies** with Alice’s **public** key. If verification passes, only someone with the private key could have produced the signature, and the bytes match what was signed. If you also need **secrecy**, add encryption.

You can do this in two broad ways in this library:

### Symmetric “signing”: HMAC

**What it is:** Both sides share one **`SymmetricKey`**. Either side can produce the same **MAC** over a message; verification recomputes and compares. There is no public/private split.

**When to use:** APIs, webhooks, or session protocols where you **already** distributed the same secret to both ends. Fast and simple; it is not, by itself, “prove identity to the whole internet” unless you already solved how Bob got that secret as Alice’s.

**In `crypto_keys`:** `algorithms.signing.hmac.sha256` (and SHA-384 / SHA-512 / `withHash`).

### Asymmetric signing: RSA, ECDSA, Ed25519

**What it is:** **Private** key creates the signature; **public** key verifies. Anyone can check a signature if they have the right public key—typical for certificates, software updates, and messages sent across untrusted channels.

**When to use:** You want **public verifiability** or many verifiers with one well-known public key. **Ed25519** is a common modern choice (raw message bytes per RFC 8032 in this package). **ECDSA** uses **NIST `Ec*`** keys; the **curve** lives on the key, the **hash** in the algorithm must match your spec. **RSA-PSS** is the usual pick for new RSA signatures; **PKCS#1 v1.5** shows up in legacy systems.

| Family | Catalog (typical) | Notes |
|--------|-------------------|--------|
| HMAC | `algorithms.signing.hmac.*` | Shared `SymmetricKey` |
| RSA PKCS#1 v1.5 | `algorithms.signing.rsa.pkcs1.*` | Legacy interop |
| RSA-PSS | `algorithms.signing.rsa.pss.*` | Prefer for new RSA |
| ECDSA | `algorithms.signing.ecdsa.*` | Curve on **`Ec*`** key |
| EdDSA | `algorithms.signing.eddsa.pure` | No extra pre-hash layer here |


### Example (Ed25519):

```dart
final pair = EdwardsKeyPair.generate(.ed25519);
final sig = pair.privateKey.createSigner(.eddsa()).sign(message);
final ok = pair.publicKey.createVerifier(.eddsa()).verify(message, sig);
```

Runnable examples: [`example/signing_example.dart`](example/signing_example.dart), [`example/ed25519_signing_example.dart`](example/ed25519_signing_example.dart).

---

## Encryption and decryption

**What it is for:** **Confidentiality**—someone who only sees ciphertext should not learn the plaintext. **Authenticated** modes (AEAD) also detect tampering.

### Symmetric encryption

**What it is:** **AES** and **ChaCha20-Poly1305** use a **`SymmetricKey`** (or key material that becomes one). Same key encrypts and decrypts.

**Why use it:** Very **fast** for large data. **AEAD** (e.g. **AES-GCM**, **ChaCha20-Poly1305**, **AES-EAX**) bundles encryption with an **authentication tag** so bit flips in transit are caught.

**When to use:** Whenever both parties can obtain the **same CEK** (see hybrid pattern below). **Never reuse** the same **nonce/IV + key** in GCM or ChaCha—store or transmit whatever the decryptor needs (`EncryptionResult`: IV, tag, optional AAD).

**Legacy note:** **AES-CBC** with PKCS padding gives confidentiality only, not integrity by itself; **CBC+HMAC** or AEAD is for when tampering matters.

### Asymmetric encryption (RSA)

**What it is:** Encrypt with the recipient’s **RSA public** key; only their **private** key decrypts. Payload size is **tiny** (modulus-bound).

**When to use:** Almost always to protect a **short secret**—especially a random **content encryption key (CEK)**—not multi-megabyte files.

### Typical hybrid pattern

Real systems combine the two:

1. Generate a random **CEK**.
2. Encrypt the bulk data with **CEK** (symmetric AEAD).
3. Protect **CEK** separately, e.g. **RSA-OAEP** to Bob’s public key, or **AES Key Wrap** with a **key encryption key (KEK)** both already share, or **ECDH/X25519** plus **[key derivation](#key-derivation)** so both sides derive the same keying material without sending CEK in the clear.

RSA is avoided for bulk data because it is slow and size-limited; symmetric crypto carries the payload.

| Mode | Catalog | Note |
|------|---------|------|
| AES-CBC PKCS7 | `algorithms.encryption.aes.cbc` | Confidentiality only; legacy |
| AES-CBC + HMAC | `algorithms.encryption.aes.cbcWithHmac.*` | Encrypt-and-MAC style |
| AES-GCM | `algorithms.encryption.aes.gcm` | Common AEAD |
| AES-EAX | `algorithms.encryption.aes.eax` | AEAD alternative |
| Key wrap | `algorithms.encryption.aes.keyWrap` | Wrap a key under a symmetric KEK (RFC 3394) |
| ChaCha-Poly1305 | `algorithms.encryption.chacha20.poly1305` | AEAD; often chosen without hardware AES |
| RSA | `algorithms.encryption.rsa.pkcs1`, `algorithms.encryption.rsa.oaep`, `algorithms.encryption.rsa.oaep256` | Short plaintext only; **`oaep256`** preferred where supported |

### Example

GCM encrypt/decrypt in two lines (symmetric key pair): 

```dart
keyPair.publicKey.createEncrypter(.gcm()).encrypt(plaintext);
keyPair.privateKey.createDecrypter(.gcm()).decrypt(result)
```

Complete sample: [`example/encryption_example.dart`](example/encryption_example.dart).

---

## Key agreement

**What it is for:** Two parties each have a **key pair** and want the **same raw secret octets** without transmitting that secret plainly. Each combines **their private key** with the **peer’s public key**; the math yields matching **shared secret** bytes on both sides—foundation for TLS-like handshakes, Signal-style ratchets, etc.

Outputs are rarely used directly as AEAD keys: run **HKDF** or **Concat-KDF** ([Key derivation](#key-derivation)) with protocol-defined **salt/info**.

**Agreement alone does not prove** you talked to the right person—combine with certs, pinning, or channel binding where your threat model requires it.

| Scheme | Catalog | Keys |
|--------|---------|------|
| ECDH (NIST EC) | `algorithms.keyAgreement.ecdh` | `EcPrivateKey` + peer `EcPublicKey` (**same curve**) |
| Montgomery DH (RFC 7748) | `algorithms.keyAgreement.montgomeryDh` | `MontgomeryPrivateKey` + peer `MontgomeryPublicKey` (**same** [MontgomeryCurve]) |

Small key-agreement example (X25519):

```dart
final alice = MontgomeryKeyPair.generate(.x25519);
final bob = MontgomeryKeyPair.generate(.x25519);
final shared = alice.privateKey.deriveSharedSecret(.montgomeryDh(peerPublicKey: bob.publicKey));
```

Agreement then HKDF, minimal spelling: `alice.privateKey.deriveSharedSecret(.montgomeryDh(peerPublicKey: bob.publicKey))` then `SecretBytes(…).deriveBits(.hkdf(hash: .sha256, …))` — [`example/montgomerydh_hkdf_example.dart`](example/montgomerydh_hkdf_example.dart), [`example/ecdh_concat_kdf_example.dart`](example/ecdh_concat_kdf_example.dart).

---

## Key derivation

**What it is for:** Turn a **password** or **already-secret octets** into **deterministic key material** of a chosen length (different inputs or salts ⇒ different outputs as designed).

**From passwords:** guessing is cheap unless you slow it down. **PBKDF2** and **Argon2id** use **salt** and **computational cost** (Argon2id adds **memory** hardness—preferred for new password storage).

**From high-entropy secrets:** e.g. output of ECDH/X25519. **HKDF** expands or splits material with **`info`** for separate subkeys; **Concat-KDF** appears in SP 800-56 and JWE-style specs. **HKDF is not for stretching low-entropy passwords**—use PBKDF2 or Argon2id there.

| Input type | Algorithms | Catalog |
|------------|-----------|---------|
| `Password` | PBKDF2, Argon2id | `algorithms.kdf.password.pbkdf2.*`, `argon2id` |
| `SecretBytes` | HKDF, Concat-KDF | `algorithms.kdf.secret.hkdf.*`, `concatKdf.*` |

Small key-derivation examples:

```dart
final fromPassword = Password.fromString('correct horse battery staple').deriveBits(
  .pbkdf2(hash: .sha256, salt: salt, iterations: 100_000, keyBitLength: 256),
);
final fromSecret = SecretBytes(shared.value).deriveBits(
  .hkdf(hash: .sha256, salt: salt, keyBitLength: 256, info: info),
);
```

**PBKDF2** runnable sample: [`example/pbkdf2_example.dart`](example/pbkdf2_example.dart).

---

## Digests (hashes)

**What they are:** One-way fingerprints of octets (`DigestAlgorithm`). In this package they usually appear **inside** other operations (HMAC, RSA schemes, OAEP, PBKDF2), not as standalone “encrypt this file.” **SHA-256+** for new designs; **SHA-1** only when a standard forces it. Catalogue: **`algorithms.digest.*`**.

---

## Key types and materials

| Kind | Types | Used for (see sections above) |
|------|--------|------------------------------|
| **Symmetric** | `SymmetricKey`, `SymmetricKeyPair` | HMAC, AES/ChaCha, key wrap with KEK |
| **RSA** | `RsaPublicKey`, `RsaPrivateKey`, `RsaKeyPair` | RSA signatures, RSA encrypt/decrypt |
| **NIST EC** | `EcPublicKey`, `EcPrivateKey`, `EcKeyPair` | ECDSA signing, ECDH agreement |
| **Edwards** | `EdwardsPublicKey`, `EdwardsPrivateKey`, `EdwardsKeyPair` | RFC 8032 pure signatures (Ed25519) |
| **Montgomery** | `MontgomeryPublicKey`, `MontgomeryPrivateKey`, `MontgomeryKeyPair` | RFC 7748 agreement (X25519) |
| **Material** | `Password`, `SecretBytes` | Stretch or derive (`deriveBits`), e.g. after agreement |

### Which key goes with which operation?

| Key type | Sign / verify | Encrypt / decrypt | Agreement |
|----------|----------------|-------------------|-----------|
| `SymmetricKey` | HMAC | AES / ChaCha / key wrap, … | — |
| `Rsa*` | RSA | RSA (short payloads) | — |
| `Ec*` | ECDSA | — | ECDH |
| `Edwards*` | EdDSA | — | — |
| `Montgomery*` | - | - | MontgomeryDH (X25519) |

### RSA vs elliptic-curve (`Ec*`)

**RSA** uses large moduli—here for **signatures** and **encrypting short blobs**. **`Ec*`** gives **ECDSA** and **ECDH** with smaller keys for comparable strength estimates. **Ed25519** and **X25519** are **separate** Curve25519 types, not interchangeable with **`Ec*`**. Prefer EC/25519 when your spec allows; keep RSA when interop or PKI requires it.

**Limitation:** Raw key objects only—no PEM/X.509/JWK parsing in this package.

---

## Key generation and importing

Most key types support both **generate** (new random key material) and **construct/import from existing material**.

Random generation:

```dart
final sym = SymmetricKey.generate(256);
final rsa = RsaKeyPair.generate(bitStrength: 2048);
final ec = EcKeyPair.generate(.p256);
final ed = EdwardsKeyPair.generate(.ed25519);
final x = MontgomeryKeyPair.generate(.x25519);
```

Import/construct from existing key material:

```dart
final importedSym = SymmetricKey(keyValue: rawBytes);
final importedRsaPub = RsaPublicKey(modulus: n, exponent: e);
final importedRsaPriv = RsaPrivateKey(
  modulus: n,
  privateExponent: d,
  firstPrimeFactor: p,
  secondPrimeFactor: q,
);
final importedEc = EcPrivateKey(eccPrivateKey: dEc, curve: .p256).asKeyPair();
final importedEd = EdwardsKeyPair.fromSeed(EdwardsCurve.ed25519, seed32);
final importedX = MontgomeryKeyPair.fromPrivateKeyBytes(
  .x25519,
  privateScalar32,
);
```

Importing note: this package intentionally works with **raw key values** (bytes / integers / coordinates / scalars). If your source is PEM, JWK, or X.509, decode/convert it outside this package first, then construct the corresponding key object here.

---

## Using the API

### The catalog

Import **`package:crypto_keys/catalog.dart`** for the top-level **`algorithms`** object: a **nested, browsable tree** of named algorithm values (good for autocomplete and docs), e.g. **`algorithms.signing.hmac.sha256`**, **`algorithms.encryption.aes.gcm`**, **`algorithms.kdf.password.pbkdf2.sha256`**, **`algorithms.keyAgreement.ecdh`**, **`algorithms.digest.*`**, and so on. Each leaf is a **typed algorithm constant**—the same conceptual primitive you can also build with factories on types from **`package:crypto_keys/crypto_keys.dart`** (`SigningAlgorithm`, `SymmetricEncryptionAlgorithm`, …); **equal values mean the same algorithm** for `createSigner`, `deriveBits`, etc.

Core **keys**, **operators**, and **material** types live in **`crypto_keys.dart`**; the catalog entrypoint is mainly **ergonomics and discovery** (see the [`catalog`](https://pub.dev/documentation/crypto_keys/latest/catalog/catalog-library.html) library API docs).

### Key-first vs algorithm-first

- **Key-first** — operations live **on the key** (`createSigner`, `deriveBits`, …); you supply the algorithm or parameter object.
- **Algorithm-first** — extensions on the catalog **algorithm** take the key (or password/secret) as the first argument (`sign`, `verify`, `deriveBits`, …).

Same HMAC-SHA256 **sign** and **verify** (equivalent results for the same `data` / `sig`):

```dart
// Key-first
kp.privateKey.createSigner(algorithms.signing.hmac.sha256).sign(data);
kp.publicKey.createVerifier(algorithms.signing.hmac.sha256).verify(data, sig);

// Algorithm-first
algorithms.signing.hmac.sha256.sign(kp.privateKey, data);
algorithms.signing.hmac.sha256.verify(kp.publicKey, data, sig);
```

Same **PBKDF2–SHA-256** derivation (same `salt` / iterations / length):

```dart
// Key-first ([Password].deriveBits with params)
password.deriveBits(
  .pbkdf2(
    hash: .sha256,
    salt: salt,
    iterations: 100_000,
    keyBitLength: 256,
  ),
);

// Algorithm-first (digest fixed by catalog entry)
algorithms.kdf.password.pbkdf2.sha256.deriveBits(
  password,
  salt: salt,
  iterations: 100_000,
  keyBitLength: 256,
);
```

Runnable: [`example/key_first_vs_algorithm_first.dart`](example/key_first_vs_algorithm_first.dart) · key-first PBKDF2: [`example/pbkdf2_example.dart`](example/pbkdf2_example.dart).

### Dot shorthand (leading `.`)

**Dot shorthands** are a **Dart 3.10+** language feature (this package requires the same SDK range): when Dart knows a parameter’s **context type**—here `SigningAlgorithm`, `SymmetricEncryptionAlgorithm`, `DigestAlgorithm`, …—you can write a **leading `.`** to pick an enum value, named constructor, or static member **without** repeating the type or a long `algorithms…` path. That keeps call sites noticeably **shorter** than the catalog or fully qualified constructor form. Many developers first meet this syntax in Flutter/UI code; it applies the same way to crypto APIs. Official overview: [Dot shorthands](https://dart.dev/language/dot-shorthands) · diagnostic reference: [`dot_shorthand_missing_context`](https://dart.dev/tools/diagnostics/dot_shorthand_missing_context).

Same algorithm value, three ways—the **last line** of each group is the **shortest** spelling (`example/dot_shorthand.dart`):

```dart
// Signing: catalog path · factory · dot shorthand (most compact)
keyPair.privateKey.createSigner(algorithms.signing.hmac.sha256);
keyPair.privateKey.createSigner(SigningAlgorithm.hmac(DigestAlgorithm.sha256));
keyPair.privateKey.createSigner(.hmac(.sha256));

// Encryption: catalog path · factory · dot shorthand (most compact)
keyPair.publicKey.createEncrypter(algorithms.encryption.aes.gcm);
keyPair.publicKey.createEncrypter(SymmetricEncryptionAlgorithm.gcm());
keyPair.publicKey.createEncrypter(.gcm());
```

All three rows in each group yield the **same** `algorithm` at runtime ([`example/dot_shorthand.dart`](example/dot_shorthand.dart) asserts it; `dart run example/dot_shorthand.dart`).

---

## Bundled example programs

From the package root (`pubspec.yaml` directory):

```sh
dart run example/key_first_vs_algorithm_first.dart
dart run example/dot_shorthand.dart
dart run example/signing_example.dart
dart run example/ed25519_signing_example.dart
dart run example/encryption_example.dart
dart run example/x25519_hkdf_example.dart
dart run example/ecdh_concat_kdf_example.dart
dart run example/pbkdf2_example.dart
```

See [example/README.md](example/README.md).

---

## Implementation

Much of the crypto is backed by [PointyCastle](https://pub.dev/packages/pointycastle); Curve25519 uses companion packages (`pubspec.yaml`).

---

## Features and bugs

Please file requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/appsup-dart/crypto_keys/issues

---

## Sponsor

Creating and maintaining this package takes time. [:heart: sponsor](https://github.com/sponsors/rbellens). More Dart packages from the same publisher: [pub.dev](https://pub.dev/packages?q=publisher%3Aappsup.be).
