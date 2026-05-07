part of '../algorithms.dart';

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
  final sha256 = SigningAlgorithmIdentifier._(
    'sig/HMAC/SHA-256',
    () => pc.HMac(pc.SHA256Digest(), 64),
  );

  /// HMAC using SHA-384
  final sha384 = SigningAlgorithmIdentifier._(
    'sig/HMAC/SHA-384',
    () => pc.HMac(pc.SHA384Digest(), 128),
  );

  /// HMAC using SHA-512
  final sha512 = SigningAlgorithmIdentifier._(
    'sig/HMAC/SHA-512',
    () => pc.HMac(pc.SHA512Digest(), 128),
  );

  _HmacSigAlgorithms() : super._('sig/HMAC');
}

class _RsaSigAlgorithms extends Identifier {
  /// RSASSA-PKCS1-v1_5 using SHA-256
  final sha256 = SigningAlgorithmIdentifier._(
    'sig/RSA/SHA-256',
    () => pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201'),
  );

  /// RSASSA-PKCS1-v1_5 using SHA-384
  final sha384 = SigningAlgorithmIdentifier._(
    'sig/RSA/SHA-384',
    () => pc.RSASigner(pc.SHA384Digest(), '0609608648016503040202'),
  );

  /// RSASSA-PKCS1-v1_5 using SHA-512
  final sha512 = SigningAlgorithmIdentifier._(
    'sig/RSA/SHA-512',
    () => pc.RSASigner(pc.SHA512Digest(), '0609608648016503040203'),
  );

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
    saltLength: 32,
  );

  /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
  late final sha384 = withParameters(
    sigHash: algorithms.digest.sha384,
    mgf1Hash: algorithms.digest.sha384,
    saltLength: 48,
  );

  /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
  late final sha512 = withParameters(
    sigHash: algorithms.digest.sha512,
    mgf1Hash: algorithms.digest.sha512,
    saltLength: 64,
  );

  SigningAlgorithmIdentifier withParameters({
    required DigestAlgorithmIdentifier sigHash,
    required DigestAlgorithmIdentifier mgf1Hash,
    required int saltLength,
  }) {
    return SigningAlgorithmIdentifier._(
      'sig/RSA/PSS/${sigHash.name}/mgf1${mgf1Hash.name}/$saltLength',
      () => _PssSignerFactory(
        sigDigest: sigHash.factory(),
        mgf1Digest: mgf1Hash.factory(),
        saltLength: saltLength,
      ),
    );
  }
}

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

class _EcdsaSigAlgorithms extends Identifier {
  /// ECDSA using P-256 and SHA-256
  final sha256 = SigningAlgorithmIdentifier._(
    'sig/ECDSA/SHA-256',
    () => pc.ECDSASigner(pc.SHA256Digest(), null),
  );

  /// ECDSA using P-384 and SHA-384
  final sha384 = SigningAlgorithmIdentifier._(
    'sig/ECDSA/SHA-384',
    () => pc.ECDSASigner(pc.SHA384Digest(), null),
  );

  /// ECDSA using P-521 and SHA-512
  final sha512 = SigningAlgorithmIdentifier._(
    'sig/ECDSA/SHA-512',
    () => pc.ECDSASigner(pc.SHA512Digest(), null),
  );

  _EcdsaSigAlgorithms() : super._('sig/ECDSA');
}

class SigningAlgorithmIdentifier<T extends pc.Algorithm>
    extends AlgorithmIdentifier<T> {
  SigningAlgorithmIdentifier._(super.name, super.factory) : super._();

  /// HMAC with the given [hash].
  static SigningAlgorithmIdentifier hmac(DigestAlgorithmIdentifier hash) {
    if (hash == DigestAlgorithmIdentifier.sha256) {
      return algorithms.signing.hmac.sha256;
    }
    if (hash == DigestAlgorithmIdentifier.sha384) {
      return algorithms.signing.hmac.sha384;
    }
    if (hash == DigestAlgorithmIdentifier.sha512) {
      return algorithms.signing.hmac.sha512;
    }
    throw UnsupportedError(
      'Unsupported HMAC hash ${hash.name}. '
      'Use SHA-256, SHA-384, or SHA-512.',
    );
  }

  /// RSA PKCS#1 v1.5 with the given [hash].
  static SigningAlgorithmIdentifier rsaPkcs1(DigestAlgorithmIdentifier hash) {
    if (hash == DigestAlgorithmIdentifier.sha256) {
      return algorithms.signing.rsa.sha256;
    }
    if (hash == DigestAlgorithmIdentifier.sha384) {
      return algorithms.signing.rsa.sha384;
    }
    if (hash == DigestAlgorithmIdentifier.sha512) {
      return algorithms.signing.rsa.sha512;
    }
    throw UnsupportedError(
      'Unsupported RSA PKCS#1 hash ${hash.name}. '
      'Use SHA-256, SHA-384, or SHA-512.',
    );
  }

  /// RSA-PSS with caller-provided parameters.
  static SigningAlgorithmIdentifier rsaPss({
    required DigestAlgorithmIdentifier sigHash,
    required DigestAlgorithmIdentifier mgf1Hash,
    required int saltLength,
  }) => algorithms.signing.rsa.pss.withParameters(
    sigHash: sigHash,
    mgf1Hash: mgf1Hash,
    saltLength: saltLength,
  );

  /// ECDSA with the given [hash].
  static SigningAlgorithmIdentifier ecdsa(DigestAlgorithmIdentifier hash) {
    if (hash == DigestAlgorithmIdentifier.sha256) {
      return algorithms.signing.ecdsa.sha256;
    }
    if (hash == DigestAlgorithmIdentifier.sha384) {
      return algorithms.signing.ecdsa.sha384;
    }
    if (hash == DigestAlgorithmIdentifier.sha512) {
      return algorithms.signing.ecdsa.sha512;
    }
    throw UnsupportedError(
      'Unsupported ECDSA hash ${hash.name}. '
      'Use SHA-256, SHA-384, or SHA-512.',
    );
  }
}
