// Long-form algorithm values vs dot shorthand (same types at runtime).
//
// Run from repo root: dart run example/dot_shorthand.dart
import 'package:crypto_keys/catalog.dart';
import 'package:crypto_keys/crypto_keys.dart';

void main() {
  final keyPair = SymmetricKeyPair.generate(256);

  // Without shorthand: catalog path
  final signerCatalog =
      keyPair.privateKey.createSigner(algorithms.signing.hmac.sha256);
  // Without shorthand: explicit factory
  final signerFactory = keyPair.privateKey
      .createSigner(SigningAlgorithm.hmac(DigestAlgorithm.sha256));
  // With dot shorthand (type context supplies SymmetricSigningAlgorithm / digest)
  final signerShorthand = keyPair.privateKey.createSigner(.hmac(.sha256));

  assert(signerCatalog.algorithm == signerFactory.algorithm);
  assert(signerCatalog.algorithm == signerShorthand.algorithm);

  final encCatalog =
      keyPair.publicKey.createEncrypter(algorithms.encryption.aes.gcm);
  final encFactory =
      keyPair.publicKey.createEncrypter(SymmetricEncryptionAlgorithm.gcm());
  final encShorthand = keyPair.publicKey.createEncrypter(.gcm());

  assert(encCatalog.algorithm == encFactory.algorithm);
  assert(encCatalog.algorithm == encShorthand.algorithm);

  print('catalog, factory, and shorthand pick the same algorithms');
}
