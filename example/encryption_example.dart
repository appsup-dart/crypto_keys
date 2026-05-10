// AES-GCM encrypt/decrypt with optional additional authenticated data (AAD).
//
// Run from repo root: dart run example/encryption_example.dart
import 'package:crypto_keys/crypto_keys.dart';
import 'dart:convert';

void main() {
  final keyPair = SymmetricKeyPair.generate(128);

  final encrypter = keyPair.publicKey.createEncrypter(.gcm());
  final result = encrypter.encrypt(
    utf8.encode('A very secret text'),
    additionalAuthenticatedData: utf8.encode('It is me'),
  );

  final decrypter = keyPair.privateKey.createDecrypter(.gcm());
  final recovered = utf8.decode(decrypter.decrypt(result));

  print(recovered);
}
