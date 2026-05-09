part of '../../algorithms.dart';

class AesCbcPkcs7HmacEncryptionAlgorithmIdentifier
    extends SymmetricEncryptionAlgorithmIdentifier {
  final DigestAlgorithmIdentifier hash;

  AesCbcPkcs7HmacEncryptionAlgorithmIdentifier(this.hash)
    : super._('enc/AES/CBC/PKCS7+HMAC/${hash.nameSuffix}');
}

class AesCbcPkcs7EncryptionAlgorithmIdentifier
    extends SymmetricEncryptionAlgorithmIdentifier {
  const AesCbcPkcs7EncryptionAlgorithmIdentifier()
    : super._('enc/AES/CBC/PKCS7');
}

class AesGcmEncryptionAlgorithmIdentifier
    extends SymmetricEncryptionAlgorithmIdentifier {
  const AesGcmEncryptionAlgorithmIdentifier() : super._('enc/AES/GCM');
}

class AesEaxEncryptionAlgorithmIdentifier
    extends SymmetricEncryptionAlgorithmIdentifier {
  const AesEaxEncryptionAlgorithmIdentifier() : super._('enc/AES/EAX');
}

class AesKeyWrapEncryptionAlgorithmIdentifier
    extends SymmetricEncryptionAlgorithmIdentifier {
  const AesKeyWrapEncryptionAlgorithmIdentifier() : super._('enc/AES/KW');
}

class ChaCha20Poly1305EncryptionAlgorithmIdentifier
    extends SymmetricEncryptionAlgorithmIdentifier {
  const ChaCha20Poly1305EncryptionAlgorithmIdentifier()
    : super._('enc/ChaCha20/Poly1305');
}

class RsaPkcs1EncryptionAlgorithmIdentifier
    extends RsaEncryptionAlgorithmIdentifier {
  const RsaPkcs1EncryptionAlgorithmIdentifier() : super._('enc/RSA/PKCS1');
}

class RsaOaepSha1EncryptionAlgorithmIdentifier
    extends RsaEncryptionAlgorithmIdentifier {
  const RsaOaepSha1EncryptionAlgorithmIdentifier()
    : super._('enc/RSA/ECB/OAEPWithSHA-1AndMGF1Padding');
}

class RsaOaepSha256EncryptionAlgorithmIdentifier
    extends RsaEncryptionAlgorithmIdentifier {
  const RsaOaepSha256EncryptionAlgorithmIdentifier()
    : super._('enc/RSA/ECB/OAEPWithSHA-256AndMGF1Padding');
}
