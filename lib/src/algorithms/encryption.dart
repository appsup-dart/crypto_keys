part of '../algorithms.dart';

class EncAlgorithms extends Identifier {
  /// Contains the identifiers for supported AES encryption algorithms
  final aes = AesEncAlgorithms();

  /// Contains the identifiers for supported RSA encryption algorithms
  final rsa = _RsaEncAlgorithms();

  /// Contains the identifiers for supported hybrid encryption algorithms
  final hybrid = HybridEncAlgorithms();

  EncAlgorithms() : super._('enc');
}

class HybridEncAlgorithms extends Identifier {
  HybridEncAlgorithms() : super._('enc/hybrid');

  EncryptionAlgorithmIdentifier withParameters({
    required int keySize,
    required Identifier curve,
    required DigestAlgorithmIdentifier hkdfHash,
  }) {
    return EncryptionAlgorithmIdentifier._(
      'enc/hybrid',
      () => pc.HKDFKeyDerivator(hkdfHash.factory()),
    );
  }
}

class AesEncAlgorithms extends Identifier {
  /// AES CBC
  final cbc = EncryptionAlgorithmIdentifier._(
    'enc/AES/CBC/PKCS7',
    () => pc.PaddedBlockCipherImpl(
      pc.PKCS7Padding(),
      pc.CBCBlockCipher(pc.AESEngine()),
    ),
  );

  final cbcWithHmac = AesWithHmacEncAlgorithms();

  /// AES GCM
  final gcm = EncryptionAlgorithmIdentifier._(
    'enc/AES/GCM',
    () => pc.GCMBlockCipher(pc.AESEngine()),
  );

  /// AES EAX
  final eax = EncryptionAlgorithmIdentifier._(
    'enc/AES/EAX',
    () => throw UnimplementedError(),
  );

  /// AES Key Wrap with default initial value
  final keyWrap = KeyManagementAlgorithmIdentifier._(
    'enc/AES/KW',
    () => pce.AESKeyWrap(),
  );

  AesEncAlgorithms() : super._('enc/AES');
}

class AesWithHmacEncAlgorithms extends Identifier {
  /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
  final sha256 = EncryptionAlgorithmIdentifier._(
    'enc/AES/CBC/PKCS7+HMAC/SHA-256',
    () => pce.AesCbcAuthenticatedCipherWithHash(
      algorithms.signing.hmac.sha256.createAlgorithm(),
    ),
  );

  /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
  final sha384 = EncryptionAlgorithmIdentifier._(
    'enc/AES/CBC/PKCS7+HMAC/SHA-384',
    () => pce.AesCbcAuthenticatedCipherWithHash(
      algorithms.signing.hmac.sha384.createAlgorithm(),
    ),
  );

  /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
  final sha512 = EncryptionAlgorithmIdentifier._(
    'enc/AES/CBC/PKCS7+HMAC/SHA-512',
    () => pce.AesCbcAuthenticatedCipherWithHash(
      algorithms.signing.hmac.sha512.createAlgorithm(),
    ),
  );

  AesWithHmacEncAlgorithms() : super._('enc/AES/CBC/PKCS7+HMAC');
}

class _RsaEncAlgorithms extends Identifier {
  /// RSAES-PKCS1-v1_5
  final pkcs1 = EncryptionAlgorithmIdentifier._(
    'enc/RSA/PKCS1',
    () => pc.PKCS1Encoding(pc.RSAEngine()),
  );

  /// RSAES OAEP using default parameters
  final oaep = EncryptionAlgorithmIdentifier._(
    'enc/RSA/ECB/OAEPWithSHA-1AndMGF1Padding',
    () => pc.OAEPEncoding.withSHA1(pc.RSAEngine()),
  );

  /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
  final oaep256 = EncryptionAlgorithmIdentifier._(
    'enc/RSA/ECB/OAEPWithSHA-256AndMGF1Padding',
    () => pc.OAEPEncoding.withSHA256(pc.RSAEngine()),
  );

  _RsaEncAlgorithms() : super._('enc/RSA');
}

class EncryptionAlgorithmIdentifier<T extends pc.Algorithm>
    extends AlgorithmIdentifier<T> {
  EncryptionAlgorithmIdentifier._(super.name, super.factory) : super._();
}

class KeyManagementAlgorithmIdentifier<T extends pc.Algorithm>
    extends EncryptionAlgorithmIdentifier<T> {
  KeyManagementAlgorithmIdentifier._(super.name, super.factory) : super._();
}
