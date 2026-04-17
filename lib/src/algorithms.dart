import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc; // TODO
import 'package:pointycastle/pointycastle.dart';

import 'pointycastle_ext.dart' as pce;

/// Contains the identifiers for supported algorithms
///
/// ## Encryption algorithms
///
/// ### AES
///
/// - [algorithms.encryption.aes.cbc] AES CBC
/// - [algorithms.encryption.aes.cbcWithHmac] AES CBC with HMAC
/// - [algorithms.encryption.aes.gcm] AES GCM
final algorithms = Algorithms();

class Algorithms {
  /// Contains the identifiers for supported signing algorithms
  final signing = _SigAlgorithms();

  /// Contains the identifiers for supported encryption algorithms
  final encryption = EncAlgorithms();

  /// Contains the identifiers for supported digest algorithms
  final digest = DigestAlgorithms();

  @Deprecated('Use encryption.aes.cbc instead.')
  // ignore: non_constant_identifier_names
  AlgorithmIdentifier get encrypting_aes_cbc => encryption.aes.cbc;

  Algorithms();
}

class DigestAlgorithms extends Identifier {
  DigestAlgorithms() : super._('digest');

  /// SHA-1 digest
  final sha1 = AlgorithmIdentifier._('digest/SHA-1', () => pc.SHA1Digest());

  /// SHA-224 digest
  final sha224 =
      AlgorithmIdentifier._('digest/SHA-224', () => pc.SHA224Digest());

  /// SHA-256 digest
  final sha256 =
      AlgorithmIdentifier._('digest/SHA-256', () => pc.SHA256Digest());

  /// SHA-384 digest
  final sha384 =
      AlgorithmIdentifier._('digest/SHA-384', () => pc.SHA384Digest());

  /// SHA-512 digest
  final sha512 =
      AlgorithmIdentifier._('digest/SHA-512', () => pc.SHA512Digest());

  /// SHA-512/t digest
  AlgorithmIdentifier sha512t(int digestSizeBytes) => AlgorithmIdentifier._(
      'digest/SHA-512/${digestSizeBytes * 8}',
      () => pc.SHA512tDigest(digestSizeBytes));

  /// MD2 digest
  final md2 = AlgorithmIdentifier._('digest/MD2', () => pc.MD2Digest());

  /// MD4 digest
  final md4 = AlgorithmIdentifier._('digest/MD4', () => pc.MD4Digest());

  /// MD5 digest
  final md5 = AlgorithmIdentifier._('digest/MD5', () => pc.MD5Digest());
}

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

  AlgorithmIdentifier withParameters(
      {required int keySize,
      required Identifier curve,
      required AlgorithmIdentifier<Digest> hkdfHash}) {
    return AlgorithmIdentifier._(
        'enc/hybrid', () => pc.HKDFKeyDerivator(hkdfHash.factory()));
  }
}

class AesEncAlgorithms extends Identifier {
  /// AES CBC
  final cbc = AlgorithmIdentifier._(
      'enc/AES/CBC/PKCS7',
      () => pc.PaddedBlockCipherImpl(
          pc.PKCS7Padding(), pc.CBCBlockCipher(pc.AESEngine())));

  final cbcWithHmac = AesWithHmacEncAlgorithms();

  /// AES GCM

  final gcm = AlgorithmIdentifier._(
      'enc/AES/GCM', () => pc.GCMBlockCipher(pc.AESEngine()));

  /// AES EAX
  final eax =
      AlgorithmIdentifier._('enc/AES/EAX', () => throw UnimplementedError());

  /// AES Key Wrap with default initial value
  final keyWrap = AlgorithmIdentifier._('enc/AES/KW', () => pce.AESKeyWrap());

  AesEncAlgorithms() : super._('enc/AES');
}

class AesWithHmacEncAlgorithms extends Identifier {
  /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
  final sha256 = AlgorithmIdentifier._(
      'enc/AES/CBC/PKCS7+HMAC/SHA-256',
      () => pce.AesCbcAuthenticatedCipherWithHash(
          algorithms.signing.hmac.sha256.createAlgorithm()));

  /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
  final sha384 = AlgorithmIdentifier._(
      'enc/AES/CBC/PKCS7+HMAC/SHA-384',
      () => pce.AesCbcAuthenticatedCipherWithHash(
          algorithms.signing.hmac.sha384.createAlgorithm()));

  /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
  final sha512 = AlgorithmIdentifier._(
      'enc/AES/CBC/PKCS7+HMAC/SHA-512',
      () => pce.AesCbcAuthenticatedCipherWithHash(
          algorithms.signing.hmac.sha512.createAlgorithm()));

  AesWithHmacEncAlgorithms() : super._('enc/AES/CBC/PKCS7+HMAC');
}

class _RsaEncAlgorithms extends Identifier {
  /// RSAES-PKCS1-v1_5
  final pkcs1 = AlgorithmIdentifier._(
      'enc/RSA/PKCS1', () => pc.PKCS1Encoding(pc.RSAEngine()));

  /// RSAES OAEP using default parameters
  final oaep = AlgorithmIdentifier._('enc/RSA/ECB/OAEPWithSHA-1AndMGF1Padding',
      () => pc.OAEPEncoding.withSHA1(pc.RSAEngine()));

  /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
  final oaep256 = AlgorithmIdentifier._(
      'enc/RSA/ECB/OAEPWithSHA-256AndMGF1Padding',
      () => pc.OAEPEncoding.withSHA256(pc.RSAEngine()));

  _RsaEncAlgorithms() : super._('enc/RSA');
}

class _SigAlgorithms extends Identifier {
  /// Contains the identifiers for supported HMAC signing algorithms
  final hmac = _HmacSigAlgorithms();

  /// Contains the identifiers for supported RSA signing algorithms
  final rsa = _RsaSigAlgorithms();

  /// Contains the identifiers for supported ECDSA signing algorithms
  final ecdsa = _EcdsaSigAlgorithms();

  _SigAlgorithms() : super._('sig');
}

class _HmacSigAlgorithms extends Identifier {
  /// HMAC using SHA-256
  final sha256 = AlgorithmIdentifier._(
      'sig/HMAC/SHA-256', () => pc.HMac(pc.SHA256Digest(), 64));

  /// HMAC using SHA-384
  final sha384 = AlgorithmIdentifier._(
      'sig/HMAC/SHA-384', () => pc.HMac(pc.SHA384Digest(), 128));

  /// HMAC using SHA-512
  final sha512 = AlgorithmIdentifier._(
      'sig/HMAC/SHA-512', () => pc.HMac(pc.SHA512Digest(), 128));

  _HmacSigAlgorithms() : super._('sig/HMAC');
}

class _RsaSigAlgorithms extends Identifier {
  /// RSASSA-PKCS1-v1_5 using SHA-256
  final sha256 = AlgorithmIdentifier._('sig/RSA/SHA-256',
      () => pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201'));

  /// RSASSA-PKCS1-v1_5 using SHA-384
  final sha384 = AlgorithmIdentifier._('sig/RSA/SHA-384',
      () => pc.RSASigner(pc.SHA384Digest(), '0609608648016503040202'));

  /// RSASSA-PKCS1-v1_5 using SHA-512
  final sha512 = AlgorithmIdentifier._('sig/RSA/SHA-512',
      () => pc.RSASigner(pc.SHA512Digest(), '0609608648016503040203'));

  /// Contains the identifiers for supported RSASSA-PSS signing algorithms
  final pss = _RsaPssAlgorithms();

  _RsaSigAlgorithms() : super._('sig/RSA');
}

class _RsaPssAlgorithms extends Identifier {
  _RsaPssAlgorithms() : super._('sig/RSA/PSS');

  /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
  late final sha256 = withParameters(
      sigHash: algorithms.digest.sha256,
      mgf1Hash: algorithms.digest.sha256,
      saltLength: 32);

  /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
  late final sha384 = withParameters(
      sigHash: algorithms.digest.sha384,
      mgf1Hash: algorithms.digest.sha384,
      saltLength: 48);

  /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
  late final sha512 = withParameters(
      sigHash: algorithms.digest.sha512,
      mgf1Hash: algorithms.digest.sha512,
      saltLength: 64);

  AlgorithmIdentifier withParameters(
      {required AlgorithmIdentifier sigHash,
      required AlgorithmIdentifier mgf1Hash,
      required int saltLength}) {
    return AlgorithmIdentifier._(
        'sig/RSA/PSS/${sigHash.name}/mgf1${mgf1Hash.name}/$saltLength',
        () => _PssSignerFactory(
            sigDigest: sigHash.factory() as pc.Digest,
            mgf1Digest: mgf1Hash.factory() as pc.Digest,
            saltLength: saltLength));
  }
}

class _PssSignerFactory implements pc.Signer {
  final pc.Digest sigDigest;
  final pc.Digest mgf1Digest;
  final int saltLength;
  late final pc.PSSSigner _delegate;

  _PssSignerFactory(
      {required this.sigDigest,
      required this.mgf1Digest,
      required this.saltLength}) {
    _delegate = pc.PSSSigner(pc.RSAEngine(), sigDigest, mgf1Digest);
  }

  @override
  String get algorithmName => _delegate.algorithmName;

  @override
  pc.Signature generateSignature(Uint8List message) =>
      _delegate.generateSignature(message);

  @override
  void init(bool forSigning, pc.CipherParameters params) {
    final keyParameters = switch (params) {
      pc.ParametersWithRandom(:final parameters) => parameters,
      pc.AsymmetricKeyParameter() => params,
      _ => throw ArgumentError(
          'Unsupported parameter type for RSA-PSS: ${params.runtimeType}')
    };
    final random = switch (params) {
      pc.ParametersWithRandom(:final random) => random,
      _ => DefaultSecureRandom(),
    };
    _delegate.init(
      forSigning,
      pc.ParametersWithSaltConfiguration(keyParameters, random, saltLength),
    );
  }

  @override
  void reset() => _delegate.reset();

  @override
  bool verifySignature(Uint8List message, pc.Signature signature) {
    if (signature is pc.PSSSignature) {
      return _delegate.verifySignature(message, signature);
    }
    if (signature is pc.RSASignature) {
      return _delegate.verifySignature(
          message, pc.PSSSignature(signature.bytes));
    }
    throw ArgumentError(
        'Expected RSA or PSS signature, got ${signature.runtimeType}');
  }
}

class _EcdsaSigAlgorithms extends Identifier {
  /// ECDSA using P-256 and SHA-256
  final sha256 = AlgorithmIdentifier._(
      'sig/ECDSA/SHA-256', () => pc.ECDSASigner(pc.SHA256Digest(), null));

  /// ECDSA using P-384 and SHA-384
  final sha384 = AlgorithmIdentifier._(
      'sig/ECDSA/SHA-384', () => pc.ECDSASigner(pc.SHA384Digest(), null));

  /// ECDSA using P-521 and SHA-512
  final sha512 = AlgorithmIdentifier._(
      'sig/ECDSA/SHA-512', () => pc.ECDSASigner(pc.SHA512Digest(), null));

  _EcdsaSigAlgorithms() : super._('sig/ECDSA');
}

/// Contains the identifiers for supported cryptographic curves
final curves = _Curves();

class _Curves {
  /// P-256
  final p256 = const Identifier._('curve/P-256');

  /// P-384
  final p384 = const Identifier._('curve/P-384');

  /// P-521
  final p521 = const Identifier._('curve/P-521');

  /// P-256K
  final p256k = const Identifier._('curve/P-256K');
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

  AlgorithmIdentifier._(super.name, this.factory) : super._();

  T createAlgorithm() => factory();
}

class DefaultSecureRandom implements pc.SecureRandom {
  final Random random = Random.secure();

  @override
  String get algorithmName => 'dart.math.Random.secure()';

  @override
  BigInt nextBigInteger(int bitLength) {
    return BigInt.parse(
        Iterable.generate(bitLength, (_) => random.nextBool() ? '1' : '0')
            .join(''),
        radix: 2);
  }

  @override
  Uint8List nextBytes(int count) =>
      Uint8List.fromList(List.generate(count, (_) => nextUint8()));

  @override
  int nextUint16() => random.nextInt(256 * 256);

  @override
  int nextUint32() => random.nextInt(256 * 256 * 256 * 256);

  @override
  int nextUint8() => random.nextInt(256);

  @override
  void seed(pc.CipherParameters params) {
    throw UnsupportedError('Seed not supported for this SecureRandom');
  }
}
