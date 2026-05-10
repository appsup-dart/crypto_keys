// Stretch a password with PBKDF2-HMAC-SHA256.
//
// Run from repo root: dart run example/pbkdf2_example.dart
import 'package:crypto_keys/crypto_keys.dart';
import 'dart:typed_data';

void main() {
  final salt = Uint8List.fromList(List.filled(16, 1));
  final key = Password.fromString('correct horse battery staple').deriveBits(
    .pbkdf2(
      hash: .sha256,
      salt: salt,
      iterations: 100_000,
      keyBitLength: 256,
    ),
  );
  print(key.length); // 32 bytes
}
