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
}

final class AesGcmEncryptionAlgorithm extends SymmetricEncryptionAlgorithm {
  const AesGcmEncryptionAlgorithm() : super();
}

final class AesEaxEncryptionAlgorithm extends SymmetricEncryptionAlgorithm {
  const AesEaxEncryptionAlgorithm() : super();
}

final class AesKeyWrapEncryptionAlgorithm extends SymmetricEncryptionAlgorithm {
  const AesKeyWrapEncryptionAlgorithm() : super();
}

final class ChaCha20Poly1305EncryptionAlgorithm
    extends SymmetricEncryptionAlgorithm {
  const ChaCha20Poly1305EncryptionAlgorithm() : super();
}

final class RsaPkcs1EncryptionAlgorithm extends RsaEncryptionAlgorithm {
  const RsaPkcs1EncryptionAlgorithm() : super();
}

final class RsaOaepSha1EncryptionAlgorithm extends RsaEncryptionAlgorithm {
  const RsaOaepSha1EncryptionAlgorithm() : super();
}

final class RsaOaepSha256EncryptionAlgorithm extends RsaEncryptionAlgorithm {
  const RsaOaepSha256EncryptionAlgorithm() : super();
}
