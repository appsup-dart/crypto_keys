import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';

/// Turns catalog KDF markers into `deriveBits` calls on `Password`/`SecretBytes`.
extension Pbkdf2KdfAlgorithmDerive on Pbkdf2KdfAlgorithm {
  /// PBKDF2 key derivation; digest is fixed by this algorithm value.
  Uint8List deriveBits(
    Password password, {
    required Uint8List salt,
    required int iterations,
    required int keyBitLength,
  }) {
    return password.deriveBits(
      Pbkdf2KdfParams(
        hash: hash,
        salt: salt,
        iterations: iterations,
        keyBitLength: keyBitLength,
      ),
    );
  }
}

extension Argon2idKdfAlgorithmDerive on Argon2idKdfAlgorithm {
  /// Argon2id key derivation (RFC 9106).
  Uint8List deriveBits(
    Password password, {
    required Uint8List salt,
    required int iterations,
    required int keyBitLength,
    required int memoryKiB,
    int lanes = 1,
    Uint8List? secret,
    Uint8List? additionalData,
  }) {
    return password.deriveBits(
      Argon2idKdfParams(
        salt: salt,
        iterations: iterations,
        keyBitLength: keyBitLength,
        memoryKiB: memoryKiB,
        lanes: lanes,
        secret: secret,
        additionalData: additionalData,
      ),
    );
  }
}

extension HkdfKdfAlgorithmDerive on HkdfKdfAlgorithm {
  /// HKDF key derivation; digest is fixed by this algorithm value.
  Uint8List deriveBits(
    SecretBytes secret, {
    required Uint8List salt,
    required int keyBitLength,
    Uint8List? info,
  }) {
    return secret.deriveBits(
      HkdfKdfParams(
        hash: hash,
        salt: salt,
        keyBitLength: keyBitLength,
        info: info,
      ),
    );
  }
}

extension ConcatKdfAlgorithmDerive on ConcatKdfAlgorithm {
  /// Concat KDF key derivation; digest is fixed by this algorithm value.
  Uint8List deriveBits(
    SecretBytes secret, {
    required int keyBitLength,
    Uint8List? otherInfo,
  }) {
    return secret.deriveBits(
      ConcatKdfKdfParams(
        hash: hash,
        keyBitLength: keyBitLength,
        otherInfo: otherInfo,
      ),
    );
  }
}
