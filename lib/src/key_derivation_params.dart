part of '../crypto_keys.dart';

/// Marker base class for key derivation parameter objects.
sealed class KeyDeriverParams {
  const KeyDeriverParams();
}

/// Marker base class for private-key derivation params (e.g. ECDH).
sealed class PrivateKeyDeriverParams extends KeyDeriverParams {
  const PrivateKeyDeriverParams();
}

/// Marker base class for EC key agreement params.
sealed class EcKeyAgreementParams extends PrivateKeyDeriverParams {
  const EcKeyAgreementParams();

  /// Shorthand factory for [EcdhKeyDeriverParams].
  static EcdhKeyDeriverParams ecdh({required EcPublicKey peerPublicKey}) =>
      EcdhKeyDeriverParams(peerPublicKey: peerPublicKey);
}

/// Marker base class for password-based derivation params (e.g. PBKDF2).
sealed class PasswordKeyDeriverParams extends KeyDeriverParams {
  const PasswordKeyDeriverParams();

  /// Shorthand factory for [Pbkdf2KeyDeriverParams].
  static Pbkdf2KeyDeriverParams pbkdf2({
    required DigestAlgorithm hash,
    required Uint8List salt,
    required int iterations,
    required int keyBitLength,
  }) => Pbkdf2KeyDeriverParams(
    hash: hash,
    salt: salt,
    iterations: iterations,
    keyBitLength: keyBitLength,
  );

  /// Argon2id (RFC 9106) with PointyCastle defaults for version (0x13) and lanes.
  static Argon2idKeyDeriverParams argon2id({
    required Uint8List salt,
    required int iterations,
    required int keyBitLength,
    required int memoryKiB,
    int lanes = 1,
    Uint8List? secret,
    Uint8List? additionalData,
  }) => Argon2idKeyDeriverParams(
    salt: salt,
    iterations: iterations,
    keyBitLength: keyBitLength,
    memoryKiB: memoryKiB,
    lanes: lanes,
    secret: secret,
    additionalData: additionalData,
  );
}

/// Marker base class for SecretBytes derivation params (e.g. HKDF/ConcatKDF).
sealed class SecretBytesKeyDeriverParams extends KeyDeriverParams {
  const SecretBytesKeyDeriverParams();

  /// Shorthand factory for [HkdfKeyDeriverParams].
  static HkdfKeyDeriverParams hkdf({
    required DigestAlgorithm hash,
    required Uint8List salt,
    required int keyBitLength,
    Uint8List? info,
  }) => HkdfKeyDeriverParams(
    hash: hash,
    salt: salt,
    keyBitLength: keyBitLength,
    info: info,
  );

  /// Shorthand factory for [ConcatKdfKeyDeriverParams].
  static ConcatKdfKeyDeriverParams concatKdf({
    required DigestAlgorithm hash,
    required int keyBitLength,
    Uint8List? otherInfo,
  }) => ConcatKdfKeyDeriverParams(
    hash: hash,
    keyBitLength: keyBitLength,
    otherInfo: otherInfo,
  );
}

/// Parameters for ECDH + Concat KDF derivation.
class EcdhKeyDeriverParams extends EcKeyAgreementParams {
  final EcPublicKey peerPublicKey;

  const EcdhKeyDeriverParams({required this.peerPublicKey});
}

/// Parameters for Argon2id password-based key derivation (RFC 9106).
///
/// [memoryKiB] is the total Argon2 memory size in kibibytes (1024-byte units),
/// matching PointyCastle [Argon2Parameters.memory]. It must be at least
/// `2 * lanes` (Argon2 block constraint).
class Argon2idKeyDeriverParams extends PasswordKeyDeriverParams {
  final Uint8List salt;
  final int iterations;
  final int memoryKiB;
  final int lanes;
  final int keyBitLength;
  final Uint8List? secret;
  final Uint8List? additionalData;

  const Argon2idKeyDeriverParams({
    required this.salt,
    required this.iterations,
    required this.keyBitLength,
    required this.memoryKiB,
    this.lanes = 1,
    this.secret,
    this.additionalData,
  });
}

/// Parameters for PBKDF2 key derivation.
class Pbkdf2KeyDeriverParams extends PasswordKeyDeriverParams {
  final DigestAlgorithm hash;
  final Uint8List salt;
  final int iterations;
  final int keyBitLength;

  const Pbkdf2KeyDeriverParams({
    required this.hash,
    required this.salt,
    required this.iterations,
    required this.keyBitLength,
  });
}

/// Parameters for HKDF key derivation.
class HkdfKeyDeriverParams extends SecretBytesKeyDeriverParams {
  final DigestAlgorithm hash;
  final Uint8List salt;
  final Uint8List? info;
  final int keyBitLength;

  const HkdfKeyDeriverParams({
    required this.hash,
    required this.salt,
    this.info,
    required this.keyBitLength,
  });
}

/// Parameters for Concat KDF key derivation.
class ConcatKdfKeyDeriverParams extends SecretBytesKeyDeriverParams {
  final DigestAlgorithm hash;
  final int keyBitLength;
  final Uint8List? otherInfo;

  const ConcatKdfKeyDeriverParams({
    required this.hash,
    required this.keyBitLength,
    this.otherInfo,
  });
}
