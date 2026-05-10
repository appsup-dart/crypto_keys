part of '../crypto_keys.dart';

/// Shared base type for secret material used by operators.
abstract mixin class KeyMaterial {}

/// A cryptographic key
abstract mixin class Key implements KeyMaterial {}

/// Weak human-chosen secret staged for slow KDFs (**PBKDF2**, **Argon2id**).
///
/// Prefer [Password.fromString] only when you genuinely have user text; derive
/// hardened bytes with `deriveBits`:
///
/// ```dart
/// pw.deriveBits(.pbkdf2(
///   hash: .sha256,
///   salt: salt,
///   iterations: 100_000,
///   keyBitLength: 256,
/// ));
/// ```
class Password with KeyMaterial {
  final Uint8List value;

  Password(List<int> value) : value = Uint8List.fromList(value);

  factory Password.fromString(String value) =>
      Password(Uint8List.fromList(utf8.encode(value)));

  /// Derives deterministic key material using [Pbkdf2KdfParams] or [Argon2idKdfParams].
  Uint8List deriveBits(PasswordKdfParams params) {
    return switch (params) {
      Pbkdf2KdfParams() => Pbkdf2(params.hash, this).deriveKey(params),
      Argon2idKdfParams() => Argon2id(this).deriveKey(params),
    };
  }
}

/// Opaque high-entropy octets (ECDH output, pre-shared secrets, etc.).
///
/// Combine with HKDF / Concat params (or **`algorithms.kdf.secret…`** catalog paths).
///
/// ```dart
/// ikm.deriveBits(.hkdf(
///   hash: .sha256,
///   salt: salt,
///   keyBitLength: 256,
///   info: protocolInfo,
/// ));
/// ```
class SecretBytes with KeyMaterial {
  final Uint8List value;

  SecretBytes(List<int> value) : value = Uint8List.fromList(value);

  /// Runs HKDF / Concat-KDF over this secret.
  Uint8List deriveBits(SecretBytesKdfParams params) {
    return switch (params) {
      HkdfKdfParams() => Hkdf(params.hash, this).deriveKey(params),
      ConcatKdfKdfParams() => ConcatKdf(params.hash, this).deriveKey(params),
    };
  }
}

/// A cryptographic public key
abstract mixin class PublicKey implements Key {}

/// A cryptographic private key
abstract mixin class PrivateKey implements Key {}

/// Capability: create signatures with a private key.
abstract mixin class SigningPrivateKey implements PrivateKey {
  /// Creates a [Signer] using this key and the specified algorithm.
  Signer createSigner(covariant SigningAlgorithm algorithm);
}

/// Capability: verify signatures with a public key.
abstract mixin class VerifyingPublicKey implements PublicKey {
  /// Creates a signature [Verifier] using this key and the specified algorithm.
  Verifier createVerifier(covariant SigningAlgorithm algorithm);
}

/// Capability: encrypt with a public key.
abstract mixin class EncryptingPublicKey implements PublicKey {
  /// Creates an [Encrypter] using this key and the specified algorithm.
  Encrypter createEncrypter(covariant EncryptionAlgorithm algorithm);
}

/// Capability: decrypt with a private key.
abstract mixin class DecryptingPrivateKey implements PrivateKey {
  /// Creates a [Decrypter] using this key and the specified algorithm.
  Decrypter createDecrypter(covariant EncryptionAlgorithm algorithm);
}

/// Capability marker for key-agreement public keys.
abstract mixin class AgreementPublicKey implements PublicKey {}

/// Capability: derive a shared secret using key agreement.
abstract mixin class AgreementPrivateKey<Params extends KeyAgreementParams>
    implements PrivateKey {
  SecretBytes deriveSharedSecret(covariant Params params);
}

/// Holds a key pair (private and public key)
abstract class KeyPair<Pub extends PublicKey, Priv extends PrivateKey> {
  /// The public key
  final Pub publicKey;

  /// The private key
  final Priv privateKey;

  /// Creates a [KeyPair] from a public and private key
  KeyPair({required this.publicKey, required this.privateKey});
}
