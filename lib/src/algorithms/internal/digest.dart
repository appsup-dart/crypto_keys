part of '../../algorithms.dart';

/// SHA-1 digest (see [DigestAlgorithm.sha1]).
final class DigestSha1 extends DigestAlgorithm {
  const DigestSha1._() : super();

  @override
  String get name => 'SHA-1';
}

/// SHA-2 digest family (SHA-224 … SHA-512, SHA-512/t).
final class DigestSha2 extends DigestAlgorithm {
  const DigestSha2._(this.outputLength, [this.digestSizeBytes])
    : assert(
        digestSizeBytes == null || outputLength == Sha2OutputLength.bits512,
        'Truncated SHA-512 (SHA-512/t) requires Sha2OutputLength.bits512.',
      );

  final Sha2OutputLength outputLength;
  final int? digestSizeBytes;

  @override
  String get name {
    final truncated = digestSizeBytes;
    if (truncated != null) return 'SHA-512/${truncated * 8}';
    switch (outputLength) {
      case Sha2OutputLength.bits224:
        return 'SHA-224';
      case Sha2OutputLength.bits256:
        return 'SHA-256';
      case Sha2OutputLength.bits384:
        return 'SHA-384';
      case Sha2OutputLength.bits512:
        return 'SHA-512';
    }
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is DigestSha2 &&
          outputLength == other.outputLength &&
          digestSizeBytes == other.digestSizeBytes;

  @override
  int get hashCode => Object.hash(outputLength, digestSizeBytes);
}

/// SHA-3 digest family.
final class DigestSha3 extends DigestAlgorithm {
  const DigestSha3._(this.outputLength) : super();

  final Sha3OutputLength outputLength;

  @override
  String get name {
    switch (outputLength) {
      case Sha3OutputLength.bits224:
        return 'SHA3-224';
      case Sha3OutputLength.bits256:
        return 'SHA3-256';
      case Sha3OutputLength.bits384:
        return 'SHA3-384';
      case Sha3OutputLength.bits512:
        return 'SHA3-512';
    }
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is DigestSha3 && outputLength == other.outputLength;

  @override
  int get hashCode => outputLength.hashCode;
}

/// Standard SHA-2 output widths (excluding SHA-1 and SHA-512/t parameterization).
enum Sha2OutputLength {
  /// SHA-224
  bits224(224),

  /// SHA-256
  bits256(256),

  /// SHA-384
  bits384(384),

  /// SHA-512 (full width); use [DigestAlgorithm.sha512t] for SHA-512/t.
  bits512(512);

  const Sha2OutputLength(this.bits);

  /// Output hash size in bits for the non-truncated variant.
  final int bits;
}

/// SHA-3 (FIPS 202) variants by output length in bits.
enum Sha3OutputLength {
  bits224(224),
  bits256(256),
  bits384(384),
  bits512(512);

  const Sha3OutputLength(this.bits);

  /// Keccak-/SHA3 output length in bits.
  final int bits;
}
