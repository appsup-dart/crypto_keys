part of '../../algorithms.dart';

final class AesCbcPkcs7HmacEncryptionAlgorithm
    extends SymmetricEncryptionAlgorithm {
  final DigestAlgorithm hash;

  const AesCbcPkcs7HmacEncryptionAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is AesCbcPkcs7HmacEncryptionAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(40, hash);
}

final class AesCbcPkcs7EncryptionAlgorithm
    extends SymmetricEncryptionAlgorithm {
  const AesCbcPkcs7EncryptionAlgorithm() : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is AesCbcPkcs7EncryptionAlgorithm;

  @override
  int get hashCode => (AesCbcPkcs7EncryptionAlgorithm).hashCode;
}

final class AesGcmEncryptionAlgorithm extends SymmetricEncryptionAlgorithm {
  const AesGcmEncryptionAlgorithm() : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is AesGcmEncryptionAlgorithm;

  @override
  int get hashCode => (AesGcmEncryptionAlgorithm).hashCode;
}

final class AesEaxEncryptionAlgorithm extends SymmetricEncryptionAlgorithm {
  const AesEaxEncryptionAlgorithm() : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is AesEaxEncryptionAlgorithm;

  @override
  int get hashCode => (AesEaxEncryptionAlgorithm).hashCode;
}

final class AesKeyWrapEncryptionAlgorithm extends SymmetricEncryptionAlgorithm {
  const AesKeyWrapEncryptionAlgorithm() : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is AesKeyWrapEncryptionAlgorithm;

  @override
  int get hashCode => (AesKeyWrapEncryptionAlgorithm).hashCode;
}

final class ChaCha20Poly1305EncryptionAlgorithm
    extends SymmetricEncryptionAlgorithm {
  const ChaCha20Poly1305EncryptionAlgorithm() : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is ChaCha20Poly1305EncryptionAlgorithm;

  @override
  int get hashCode => (ChaCha20Poly1305EncryptionAlgorithm).hashCode;
}

final class RsaPkcs1EncryptionAlgorithm extends RsaEncryptionAlgorithm {
  const RsaPkcs1EncryptionAlgorithm() : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is RsaPkcs1EncryptionAlgorithm;

  @override
  int get hashCode => (RsaPkcs1EncryptionAlgorithm).hashCode;
}

final class RsaOaepSha1EncryptionAlgorithm extends RsaEncryptionAlgorithm {
  const RsaOaepSha1EncryptionAlgorithm() : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is RsaOaepSha1EncryptionAlgorithm;

  @override
  int get hashCode => (RsaOaepSha1EncryptionAlgorithm).hashCode;
}

final class RsaOaepSha256EncryptionAlgorithm extends RsaEncryptionAlgorithm {
  const RsaOaepSha256EncryptionAlgorithm() : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is RsaOaepSha256EncryptionAlgorithm;

  @override
  int get hashCode => (RsaOaepSha256EncryptionAlgorithm).hashCode;
}
