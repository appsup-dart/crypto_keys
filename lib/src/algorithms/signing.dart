part of '../algorithms.dart';

class _PssSignerFactory implements pc.Signer {
  final pc.Digest sigDigest;
  final pc.Digest mgf1Digest;
  final int saltLength;
  late final pc.PSSSigner _delegate;

  _PssSignerFactory({
    required this.sigDigest,
    required this.mgf1Digest,
    required this.saltLength,
  }) {
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
        'Unsupported parameter type for RSA-PSS: ${params.runtimeType}',
      ),
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
        message,
        pc.PSSSignature(signature.bytes),
      );
    }
    throw ArgumentError(
      'Expected RSA or PSS signature, got ${signature.runtimeType}',
    );
  }
}

/// Identifier for signing and signature-verification algorithms.
abstract class SigningAlgorithmIdentifier extends AlgorithmIdentifier {
  SigningAlgorithmIdentifier._(super.name, super.factory) : super._();

  /// HMAC with the given [hash].
  static SymmetricSigningAlgorithmIdentifier hmac(
    DigestAlgorithmIdentifier hash,
  ) => .hmac(hash);

  /// RSA PKCS#1 v1.5 with the given [hash].
  static RsaSigningAlgorithmIdentifier rsaPkcs1(
    DigestAlgorithmIdentifier hash,
  ) => .pkcs1(hash);

  /// RSA-PSS with caller-provided parameters.
  static RsaSigningAlgorithmIdentifier rsaPss({
    required DigestAlgorithmIdentifier sigHash,
    required DigestAlgorithmIdentifier mgf1Hash,
    required int saltLength,
  }) => .pss(sigHash, mgf1Hash: mgf1Hash, saltLength: saltLength);

  /// ECDSA with the given [hash].
  static EcSigningAlgorithmIdentifier ecdsa(DigestAlgorithmIdentifier hash) =>
      .ecdsa(hash);

  /// Ed25519 pure signatures (RFC 8032).
  static final Ed25519SigningAlgorithmIdentifier ed25519 =
      Ed25519SigningAlgorithmIdentifier();
}

/// Symmetric signing algorithm identifiers (HMAC family).
class SymmetricSigningAlgorithmIdentifier extends SigningAlgorithmIdentifier {
  SymmetricSigningAlgorithmIdentifier._(super.name, super.factory) : super._();

  /// HMAC with the given [hash].
  factory SymmetricSigningAlgorithmIdentifier.hmac(
    DigestAlgorithmIdentifier hash,
  ) => SymmetricSigningAlgorithmIdentifier._(
    'sig/HMAC/${hash.nameSuffix}',
    () => pc.HMac(hash.createAlgorithm() as pc.Digest, hash.blockLength),
  );
}

/// Base class for asymmetric signing algorithm identifiers.
class AsymmetricSigningAlgorithmIdentifier extends SigningAlgorithmIdentifier {
  AsymmetricSigningAlgorithmIdentifier._(super.name, super.factory) : super._();
}

/// RSA signing algorithm identifiers.
class RsaSigningAlgorithmIdentifier
    extends AsymmetricSigningAlgorithmIdentifier {
  RsaSigningAlgorithmIdentifier._(super.name, super.factory) : super._();

  /// RSASSA-PKCS1-v1_5 with the given digest.
  factory RsaSigningAlgorithmIdentifier.pkcs1(DigestAlgorithmIdentifier hash) =>
      RsaSigningAlgorithmIdentifier._(
        'sig/RSA/${hash.nameSuffix}',
        () => pc.RSASigner(
          hash.createAlgorithm() as pc.Digest,
          hash.rsaPkcs1DigestIdentifierHex,
        ),
      );

  /// RSASSA-PSS with caller-provided or defaulted parameters.
  ///
  /// Defaults:
  /// - `mgf1Hash`: same as [sigHash]
  /// - `saltLength`: digest output size of [sigHash] (in bytes)
  factory RsaSigningAlgorithmIdentifier.pss(
    DigestAlgorithmIdentifier sigHash, {
    DigestAlgorithmIdentifier? mgf1Hash,
    int? saltLength,
  }) {
    final resolvedMgf1Hash = mgf1Hash ?? sigHash;
    final resolvedSaltLength =
        saltLength ?? (sigHash.createAlgorithm() as pc.Digest).digestSize;
    return RsaSigningAlgorithmIdentifier._(
      'sig/RSA/PSS/${sigHash.name}/mgf1${resolvedMgf1Hash.name}/$resolvedSaltLength',
      () => _PssSignerFactory(
        sigDigest: sigHash.createAlgorithm() as pc.Digest,
        mgf1Digest: resolvedMgf1Hash.createAlgorithm() as pc.Digest,
        saltLength: resolvedSaltLength,
      ),
    );
  }
}

/// ECDSA signing algorithm identifiers.
class EcSigningAlgorithmIdentifier
    extends AsymmetricSigningAlgorithmIdentifier {
  EcSigningAlgorithmIdentifier._(super.name, super.factory) : super._();

  factory EcSigningAlgorithmIdentifier.ecdsa(DigestAlgorithmIdentifier hash) =>
      EcSigningAlgorithmIdentifier._(
        'sig/ECDSA/${hash.nameSuffix}',
        () => pc.ECDSASigner(hash.createAlgorithm() as pc.Digest, null),
      );
}

/// Ed25519 signing (RFC 8032).
///
/// Signs and verifies the **raw** message bytes (no separate digest step).
class Ed25519SigningAlgorithmIdentifier
    extends AsymmetricSigningAlgorithmIdentifier {
  Ed25519SigningAlgorithmIdentifier._(super.name, super.factory) : super._();

  Ed25519SigningAlgorithmIdentifier()
    : this._('sig/Ed25519', () => _Ed25519PcPlaceholder.instance);
}

/// Satisfies [Operator] without delegating to PointyCastle signing.
class _Ed25519PcPlaceholder implements pc.Algorithm {
  _Ed25519PcPlaceholder._();
  static final _Ed25519PcPlaceholder instance = _Ed25519PcPlaceholder._();

  @override
  String get algorithmName => 'Ed25519';
}
