part of '../algorithms.dart';

class Algorithms {
  /// Contains the identifiers for supported signing algorithms
  final signing = _SigAlgorithms();

  /// Contains the identifiers for supported encryption algorithms
  final encryption = EncAlgorithms();

  /// Contains the identifiers for supported digest algorithms
  final digest = DigestAlgorithms();

  /// Contains the identifiers for supported key derivation algorithms
  final derivation = DerivationAlgorithms();

  @Deprecated('Use encryption.aes.cbc instead.')
  // ignore: non_constant_identifier_names
  EncryptionAlgorithmIdentifier get encrypting_aes_cbc => encryption.aes.cbc;

  Algorithms();
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
      Iterable.generate(
        bitLength,
        (_) => random.nextBool() ? '1' : '0',
      ).join(''),
      radix: 2,
    );
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
