// ECDH then Concat-KDF (SP 800-56 style): shared secret bytes to derived key schedule.
//
// Run from repo root: dart run example/ecdh_concat_kdf_example.dart
import 'package:crypto_keys/crypto_keys.dart';
import 'dart:typed_data';

void main() {
  final my = EcKeyPair.generate(Curve.p256);
  final peer = EcKeyPair.generate(Curve.p256);
  final otherInfo = Uint8List.fromList([1, 2, 3, 4]);

  final shared = my.privateKey.deriveSharedSecret(
    .ecdh(peerPublicKey: peer.publicKey),
  );
  final derived = shared.deriveBits(
    .concatKdf(hash: .sha256, keyBitLength: 256, otherInfo: otherInfo),
  );

  print('derived ${derived.length} octets (${derived.length * 8} bits)');
}
