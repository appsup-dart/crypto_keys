library crypto_keys.algorithms;

import 'package:pointycastle/export.dart' as pc;
import 'dart:math' show Random;
import 'pointycastle_ext.dart' as pc;
import 'dart:typed_data';

/// Contains the identifiers for supported algorithms
///
/// ## Encryption algorithms
///
/// ### AES
///
/// - [algorithms.encryption.aes.cbc] AES CBC
/// - [algorithms.encryption.aes.cbcWithHmac] AES CBC with HMAC
/// - [algorithms.encryption.aes.gcm] AES GCM
final algorithms = new Algorithms();

class Algorithms {
  /// Contains the identifiers for supported signing algorithms
  final signing = new _SigAlgorithms();

  /// Contains the identifiers for supported encryption algorithms
  final encryption = new EncAlgorithms();

  final encrypting_aes_cbc = new AlgorithmIdentifier._(
      "enc/AES/CBC/PKCS7",
      () => new pc.PaddedBlockCipherImpl(new pc.PKCS7Padding(),
          new pc.CBCBlockCipher(new pc.AESFastEngine())));

  Algorithms();
}

class EncAlgorithms extends Identifier {
  /// Contains the identifiers for supported AES encryption algorithms
  final aes = new AesEncAlgorithms();

  /// Contains the identifiers for supported RSA encryption algorithms
  final rsa = new _RsaEncAlgorithms();

  EncAlgorithms() : super._("enc");
}

class AesEncAlgorithms extends Identifier {
  /// AES CBC
  final cbc = new AlgorithmIdentifier._(
      "enc/AES/CBC/PKCS7",
      () => new pc.PaddedBlockCipherImpl(new pc.PKCS7Padding(),
          new pc.CBCBlockCipher(new pc.AESFastEngine())));

  final cbcWithHmac = new AesWithHmacEncAlgorithms();

  /// AES GCM
  final gcm = new AlgorithmIdentifier._(
      "enc/AES/GCM", () => new pc.GCMBlockCipher(new pc.AESFastEngine()));

  /// AES Key Wrap with default initial value
  final keyWrap =
      new AlgorithmIdentifier._("enc/AES/KW", () => pc.AESKeyWrap());

  AesEncAlgorithms() : super._("enc/AES");
}

class AesWithHmacEncAlgorithms extends Identifier {
  /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
  final sha256 = new AlgorithmIdentifier._(
      "enc/AES/CBC/PKCS7+HMAC/SHA-256",
      () => new pc.AesCbcAuthenticatedCipherWithHash(
          algorithms.signing.hmac.sha256.createAlgorithm()));

  /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
  final sha384 = new AlgorithmIdentifier._(
      "enc/AES/CBC/PKCS7+HMAC/SHA-384",
      () => new pc.AesCbcAuthenticatedCipherWithHash(
          algorithms.signing.hmac.sha384.createAlgorithm()));

  /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
  final sha512 = new AlgorithmIdentifier._(
      "enc/AES/CBC/PKCS7+HMAC/SHA-512",
      () => new pc.AesCbcAuthenticatedCipherWithHash(
          algorithms.signing.hmac.sha512.createAlgorithm()));

  AesWithHmacEncAlgorithms() : super._("enc/AES/CBC/PKCS7+HMAC");
}

class _RsaEncAlgorithms extends Identifier {
  /// RSAES-PKCS1-v1_5
  final pkcs1 = new AlgorithmIdentifier._(
      "enc/RSA/PKCS1", () => new pc.PKCS1Encoding(new pc.RSAEngine()));

  /// RSAES OAEP using default parameters
  final oaep = new AlgorithmIdentifier._(
      "enc/RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
      () => throw new UnimplementedError("RSA OAEP mode not implemented"));

  _RsaEncAlgorithms() : super._("enc/RSA");
}

class _SigAlgorithms extends Identifier {
  /// Contains the identifiers for supported HMAC signing algorithms
  final hmac = new _HmacSigAlgorithms();

  /// Contains the identifiers for supported RSA signing algorithms
  final rsa = new _RsaSigAlgorithms();

  /// Contains the identifiers for supported ECDSA signing algorithms
  final ecdsa = new _EcdsaSigAlgorithms();

  _SigAlgorithms() : super._("sig");
}

class _HmacSigAlgorithms extends Identifier {
  /// HMAC using SHA-256
  final sha256 = new AlgorithmIdentifier._(
      "sig/HMAC/SHA-256", () => new pc.HMac(new pc.SHA256Digest(), 64));

  /// HMAC using SHA-384
  final sha384 = new AlgorithmIdentifier._(
      "sig/HMAC/SHA-384", () => new pc.HMac(new pc.SHA384Digest(), 128));

  /// HMAC using SHA-512
  final sha512 = new AlgorithmIdentifier._(
      "sig/HMAC/SHA-512", () => new pc.HMac(new pc.SHA512Digest(), 128));

  _HmacSigAlgorithms() : super._("sig/HMAC");
}

class _RsaSigAlgorithms extends Identifier {
  /// RSASSA-PKCS1-v1_5 using SHA-256
  final sha256 = new AlgorithmIdentifier._("sig/RSA/SHA-256",
      () => new pc.RSASigner(new pc.SHA256Digest(), "0609608648016503040201"));

  /// RSASSA-PKCS1-v1_5 using SHA-384
  final sha384 = new AlgorithmIdentifier._("sig/RSA/SHA-384",
      () => new pc.RSASigner(new pc.SHA384Digest(), "0609608648016503040202"));

  /// RSASSA-PKCS1-v1_5 using SHA-512
  final sha512 = new AlgorithmIdentifier._("sig/RSA/SHA-512",
      () => new pc.RSASigner(new pc.SHA512Digest(), "0609608648016503040203"));

  _RsaSigAlgorithms() : super._("sig/RSA");
}

class _EcdsaSigAlgorithms extends Identifier {
  /// ECDSA using P-256 and SHA-256
  final sha256 = new AlgorithmIdentifier._("sig/ECDSA/SHA-256",
      () => new pc.ECDSASigner(new pc.SHA256Digest(), null));

  /// ECDSA using P-384 and SHA-384
  final sha384 = new AlgorithmIdentifier._("sig/ECDSA/SHA-384",
      () => new pc.ECDSASigner(new pc.SHA384Digest(), null));

  /// ECDSA using P-521 and SHA-512
  final sha512 = new AlgorithmIdentifier._("sig/ECDSA/SHA-512",
      () => new pc.ECDSASigner(new pc.SHA512Digest(), null));

  _EcdsaSigAlgorithms() : super._("sig/ECDSA");
}

/// Contains the identifiers for supported cryptographic curves
final curves = new _Curves();

class _Curves {
  /// P-256
  final p256 = const Identifier._("curve/P-256");

  /// P-384
  final p384 = const Identifier._("curve/P-384");

  /// P-521
  final p521 = const Identifier._("curve/P-521");
}

/// An identifier for uniquely identify algorithms and other objects
class Identifier {
  final String name;

  const Identifier._(this.name);

  @override
  int get hashCode => name.hashCode;

  @override
  bool operator ==(other) => other is Identifier && other.name == name;
}

class AlgorithmIdentifier<T extends pc.Algorithm> extends Identifier {
  final T Function() factory;

  AlgorithmIdentifier._(String name, this.factory) : super._(name);

  static final _jwaAlgorithms = <String, AlgorithmIdentifier>{
    // Algorithms for JWS

    /// HMAC using SHA-256
    "HS256": algorithms.signing.hmac.sha256,

    /// HMAC using SHA-384
    "HS384": algorithms.signing.hmac.sha384,

    /// HMAC using SHA-512
    "HS512": algorithms.signing.hmac.sha512,

    /// RSASSA-PKCS1-v1_5 using SHA-256
    "RS256": algorithms.signing.rsa.sha256,

    /// RSASSA-PKCS1-v1_5 using SHA-384
    "RS384": algorithms.signing.rsa.sha384,

    /// RSASSA-PKCS1-v1_5 using SHA-512
    "RS512": algorithms.signing.rsa.sha512,

    /// ECDSA using P-256 and SHA-256
    "ES256": algorithms.signing.ecdsa.sha256,

    /// ECDSA using P-384 and SHA-384
    "ES384": algorithms.signing.ecdsa.sha384,

    /// ECDSA using P-512 and SHA-512
    "ES512": algorithms.signing.ecdsa.sha512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    "PS256": null,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    "PS384": null,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    "PS512": null,

    /// No digital signature or MAC
    "none": null,

    // Algorithms for JWE
    /// RSAES-PKCS1-v1_5
    "RSA1_5": algorithms.encryption.rsa.pkcs1,

    /// RSAES OAEP using default parameters
    "RSA-OAEP": algorithms.encryption.rsa.oaep,

    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    "RSA-OAEP-256": null, // TODO
    /// AES Key Wrap with default initial value using 128-bit key
    "A128KW": algorithms.encryption.aes.keyWrap, // TODO
    /// AES Key Wrap with default initial value using 192-bit key
    "A192KW": algorithms.encryption.aes.keyWrap, // TODO
    /// AES Key Wrap with default initial value using 256-bit key
    "A256KW": algorithms.encryption.aes.keyWrap, // TODO
    /// Direct use of a shared symmetric key as the CEK
    "dir": null,

    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    "ECDH-ES": null,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW"
    "ECDH-ES+A128KW": null,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
    "ECDH-ES+A192KW": null,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
    "ECDH-ES+A256KW": null,

    /// Key wrapping with AES GCM using 128-bit key
    "A128GCMKW": null,

    /// Key wrapping with AES GCM using 192-bit key
    "A192GCMKW": null,

    /// Key wrapping with AES GCM using 256-bit key
    "A256GCMKW": null,

    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    "PBES2-HS256+A128KW": null,

    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    "PBES2-HS384+A192KW": null,

    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    "PBES2-HS512+A256KW": null,

    // Encryption Algorithms for JWE
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
    "A128CBC-HS256": algorithms.encryption.aes.cbcWithHmac.sha256,

    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
    "A192CBC-HS384": algorithms.encryption.aes.cbcWithHmac.sha384,

    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
    "A256CBC-HS512": algorithms.encryption.aes.cbcWithHmac.sha512,

    /// AES GCM using 128-bit key
    "A128GCM": algorithms.encryption.aes.gcm, // TODO
    /// AES GCM using 192-bit key
    "A192GCM": algorithms.encryption.aes.gcm, // TODO
    /// AES GCM using 256-bit key
    "A256GCM": algorithms.encryption.aes.gcm, // TODO
  };

  static AlgorithmIdentifier getByJwaName(String alg) {
    var i = _jwaAlgorithms[alg];
    if (i == null && alg != "none") {
      if (_jwaAlgorithms.containsKey(alg))
        throw new UnimplementedError("Algorithm '$alg' not implemented");
      throw new UnsupportedError("Algorithm '$alg' not supported");
    }
    return i;
  }

  T createAlgorithm() => factory();
}

class DefaultSecureRandom implements pc.SecureRandom {
  final Random random = new Random.secure();

  @override
  String get algorithmName => "dart.math.Random.secure()";

  @override
  BigInt nextBigInteger(int bitLength) {
    return BigInt.parse(
        new Iterable.generate(bitLength, (_) => random.nextBool() ? "1" : "0")
            .join(""),
        radix: 2);
  }

  @override
  Uint8List nextBytes(int count) =>
      new Uint8List.fromList(new List.generate(count, (_) => nextUint8()));

  @override
  int nextUint16() => random.nextInt(256 * 256);

  @override
  int nextUint32() => random.nextInt(256 * 256 * 256 * 256);

  @override
  int nextUint8() => random.nextInt(256);

  @override
  void seed(pc.CipherParameters params) {
    throw new UnsupportedError("Seed not supported for this SecureRandom");
  }
}
