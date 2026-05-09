import 'dart:typed_data';

import '../crypto_keys.dart';

/// Sealed base type for parameters passed to [Password.deriveBits] and
/// [SecretBytes.deriveBits].
sealed class KdfParams {
  const KdfParams();
}

/// Password-based KDF parameters ([Password.deriveBits]).
sealed class PasswordKdfParams extends KdfParams {
  const PasswordKdfParams();

  static PasswordKdfParams pbkdf2({
    required DigestAlgorithm hash,
    required Uint8List salt,
    required int iterations,
    required int keyBitLength,
  }) => Pbkdf2KdfParams(
    hash: hash,
    salt: salt,
    iterations: iterations,
    keyBitLength: keyBitLength,
  );

  /// Argon2id (RFC 9106) with PointyCastle defaults for version (0x13) and lanes.
  static PasswordKdfParams argon2id({
    required Uint8List salt,
    required int iterations,
    required int keyBitLength,
    required int memoryKiB,
    int lanes = 1,
    Uint8List? secret,
    Uint8List? additionalData,
  }) => Argon2idKdfParams(
    salt: salt,
    iterations: iterations,
    keyBitLength: keyBitLength,
    memoryKiB: memoryKiB,
    lanes: lanes,
    secret: secret,
    additionalData: additionalData,
  );
}

/// Parameters for KDFs keyed by [SecretBytes] ([SecretBytes.deriveBits]).
sealed class SecretBytesKdfParams extends KdfParams {
  const SecretBytesKdfParams();

  static SecretBytesKdfParams hkdf({
    required DigestAlgorithm hash,
    required Uint8List salt,
    required int keyBitLength,
    Uint8List? info,
  }) => HkdfKdfParams(
    hash: hash,
    salt: salt,
    keyBitLength: keyBitLength,
    info: info,
  );

  static SecretBytesKdfParams concatKdf({
    required DigestAlgorithm hash,
    required int keyBitLength,
    Uint8List? otherInfo,
  }) => ConcatKdfKdfParams(
    hash: hash,
    keyBitLength: keyBitLength,
    otherInfo: otherInfo,
  );
}

/// Parameters for Argon2id password-based key derivation (RFC 9106).
///
/// [memoryKiB] is the total Argon2 memory size in kibibytes (1024-byte units),
/// matching PointyCastle [Argon2Parameters.memory]. It must be at least
/// `2 * lanes` (Argon2 block constraint).
class Argon2idKdfParams extends PasswordKdfParams {
  final Uint8List salt;
  final int iterations;
  final int memoryKiB;
  final int lanes;
  final int keyBitLength;
  final Uint8List? secret;
  final Uint8List? additionalData;

  const Argon2idKdfParams({
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
class Pbkdf2KdfParams extends PasswordKdfParams {
  final DigestAlgorithm hash;
  final Uint8List salt;
  final int iterations;
  final int keyBitLength;

  const Pbkdf2KdfParams({
    required this.hash,
    required this.salt,
    required this.iterations,
    required this.keyBitLength,
  });
}

/// Parameters for HKDF key derivation.
class HkdfKdfParams extends SecretBytesKdfParams {
  final DigestAlgorithm hash;
  final Uint8List salt;
  final Uint8List? info;
  final int keyBitLength;

  const HkdfKdfParams({
    required this.hash,
    required this.salt,
    this.info,
    required this.keyBitLength,
  });
}

/// Parameters for Concat KDF key derivation.
class ConcatKdfKdfParams extends SecretBytesKdfParams {
  final DigestAlgorithm hash;
  final int keyBitLength;
  final Uint8List? otherInfo;

  const ConcatKdfKdfParams({
    required this.hash,
    required this.keyBitLength,
    this.otherInfo,
  });
}
