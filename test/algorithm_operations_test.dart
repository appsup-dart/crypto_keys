import 'package:crypto_keys/crypto_keys.dart';
import 'package:test/test.dart';

void main() {
  test('every SigningAlgorithm resolves sign / verify extensions', () {
    void verify(SigningAlgorithm algorithm) {
      switch (algorithm) {
        case SymmetricSigningAlgorithm():
          algorithm.sign;
          algorithm.verify;
        case RsaSigningAlgorithm():
          algorithm.sign;
          algorithm.verify;
        case EcSigningAlgorithm():
          algorithm.sign;
          algorithm.verify;
        case Ed25519SigningAlgorithm():
          algorithm.sign;
          algorithm.verify;
      }
    }

    verify;
  });

  test('every EncryptionAlgorithm resolves encrypt / decrypt extensions', () {
    void verify(EncryptionAlgorithm algorithm) {
      switch (algorithm) {
        case SymmetricEncryptionAlgorithm():
          algorithm.encrypt;
          algorithm.decrypt;
        case RsaEncryptionAlgorithm():
          algorithm.encrypt;
          algorithm.decrypt;
      }
    }

    verify;
  });

  test('every KeyAgreementAlgorithm has a deriveSharedSecret extension', () {
    void verify(KeyAgreementAlgorithm algorithm) {
      switch (algorithm) {
        case EcdhKeyAgreementAlgorithm():
          algorithm.deriveSharedSecret;
        case X25519KeyAgreementAlgorithm():
          algorithm.deriveSharedSecret;
      }
    }

    verify;
  });

  test('every KdfAlgorithm has a deriveBits extension method', () {
    // Analysis-time guard: exhaustive switch on [KdfAlgorithm] and `.deriveBits`
    // resolving on each concrete type (needs an extension); `dart analyze`
    // fails when a variant is missing or lacks the method.
    void verify(KdfAlgorithm algorithm) {
      switch (algorithm) {
        case Pbkdf2KdfAlgorithm():
          algorithm.deriveBits;
        case Argon2idKdfAlgorithm():
          algorithm.deriveBits;
        case ConcatKdfAlgorithm():
          algorithm.deriveBits;
        case HkdfKdfAlgorithm():
          algorithm.deriveBits;
      }
    }

    verify;
  });
}
