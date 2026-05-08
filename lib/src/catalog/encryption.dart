part of '../catalog.dart';

/// Browsable catalog of encryption algorithm identifiers.
class EncryptionAlgorithms extends Identifier {
  /// Contains the identifiers for supported AES encryption algorithms
  final aes = const AesEncryptionAlgorithms._();

  /// Contains the identifiers for supported RSA encryption algorithms
  final rsa = const RsaEncryptionAlgorithms._();

  const EncryptionAlgorithms._() : super('enc');
}

/// Browsable catalog of AES encryption algorithms.
class AesEncryptionAlgorithms extends Identifier {
  /// AES CBC
  SymmetricEncryptionAlgorithmIdentifier get cbc => .cbcWithPkcs7();

  /// AES-CBC + HMAC authenticated encryption variants.
  final cbcWithHmac = const AesWithHmacEncryptionAlgorithms._();

  /// AES GCM
  SymmetricEncryptionAlgorithmIdentifier get gcm => .gcm();

  /// AES EAX
  SymmetricEncryptionAlgorithmIdentifier get eax => .eax();

  /// AES Key Wrap with default initial value
  SymmetricEncryptionAlgorithmIdentifier get keyWrap => .keyWrap();

  const AesEncryptionAlgorithms._() : super('enc/AES');
}

/// Browsable catalog of AES-CBC-HMAC authenticated encryption algorithms.
class AesWithHmacEncryptionAlgorithms extends Identifier {
  /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
  SymmetricEncryptionAlgorithmIdentifier get sha256 => .cbcWithHmac(.sha256);

  /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
  SymmetricEncryptionAlgorithmIdentifier get sha384 => .cbcWithHmac(.sha384);

  /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
  SymmetricEncryptionAlgorithmIdentifier get sha512 => .cbcWithHmac(.sha512);

  const AesWithHmacEncryptionAlgorithms._() : super('enc/AES/CBC/PKCS7+HMAC');
}

/// Browsable catalog of RSA encryption algorithms.
class RsaEncryptionAlgorithms extends Identifier {
  /// RSAES-PKCS1-v1_5
  RsaEncryptionAlgorithmIdentifier get pkcs1 => .pkcs1();

  /// RSAES OAEP using default parameters
  RsaEncryptionAlgorithmIdentifier get oaep => .oaepWithSha1();

  /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
  RsaEncryptionAlgorithmIdentifier get oaep256 => .oaepWithSha256();

  const RsaEncryptionAlgorithms._() : super('enc/RSA');
}
