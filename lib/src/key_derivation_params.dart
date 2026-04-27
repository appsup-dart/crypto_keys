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
    required DigestAlgorithmIdentifier hash,
    required Uint8List salt,
    required int iterations,
    required int keyBitLength,
  }) => Pbkdf2KeyDeriverParams(
    hash: hash,
    salt: salt,
    iterations: iterations,
    keyBitLength: keyBitLength,
  );
}

/// Marker base class for SecretBytes derivation params (e.g. HKDF/ConcatKDF).
sealed class SecretBytesKeyDeriverParams extends KeyDeriverParams {
  const SecretBytesKeyDeriverParams();

  /// Shorthand factory for [HkdfKeyDeriverParams].
  static HkdfKeyDeriverParams hkdf({
    required DigestAlgorithmIdentifier hash,
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
    required DigestAlgorithmIdentifier hash,
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

/// Parameters for PBKDF2 key derivation.
class Pbkdf2KeyDeriverParams extends PasswordKeyDeriverParams {
  final DigestAlgorithmIdentifier hash;
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
  final DigestAlgorithmIdentifier hash;
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
  final DigestAlgorithmIdentifier hash;
  final int keyBitLength;
  final Uint8List? otherInfo;

  const ConcatKdfKeyDeriverParams({
    required this.hash,
    required this.keyBitLength,
    this.otherInfo,
  });
}
