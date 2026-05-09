import 'dart:typed_data';

import 'package:x25519/x25519.dart' as x25519_impl;

import '../../crypto_keys.dart';
import '../key_agreement_params.dart';
import '../pointycastle_ext.dart' as pc;
import 'ec.dart';

abstract class KeyAgreement<T extends KeyAgreementParams, K extends PrivateKey>
    extends Operator<K> {
  KeyAgreement(KeyAgreementAlgorithm super.algorithm, super.key);

  SecretBytes deriveSharedSecret(T params);
}

/// Generic ECDH shared-secret derivation helpers.
///
/// These helpers derive the ECDH shared secret from EC key pairs.
class EcdhKeyAgreement
    extends KeyAgreement<EcdhKeyAgreementParams, EcPrivateKey> {
  EcdhKeyAgreement(EcPrivateKey key) : super(.ecdh(), key);

  /// Derives the ECDH shared secret for the given EC key pair.
  ///
  /// The input keys must both be EC keys and use the same curve (`P-256`,
  /// `P-384`, or `P-521`). The output is fixed-length, big-endian bytes.
  @override
  SecretBytes deriveSharedSecret(EcdhKeyAgreementParams params) {
    final privateKey = keyMaterial;
    final publicKey = params.peerPublicKey;
    if (privateKey.curve != publicKey.curve) {
      throw ArgumentError(
        'ECDH requires matching curves, got '
        '${privateKey.curve.name} and ${publicKey.curve.name}',
      );
    }

    final domain = ecDomainParametersForCurve(privateKey.curve);
    final pcPrivate = pc.ECPrivateKey(privateKey.eccPrivateKey, domain);
    final pcPublic = pc.ECPublicKey(
      domain.curve.createPoint(publicKey.xCoordinate, publicKey.yCoordinate),
      domain,
    );

    final agreement = pc.ECDHBasicAgreement()..init(pcPrivate);
    final zInt = agreement.calculateAgreement(pcPublic);
    return SecretBytes(_encodeBigIntFixedWidth(zInt, agreement.getFieldSize()));
  }

  Uint8List _encodeBigIntFixedWidth(BigInt value, int length) {
    if (value < BigInt.zero) {
      throw ArgumentError.value(value, 'value', 'Must be non-negative');
    }
    final bytes = Uint8List(length);
    var v = value;
    for (var i = length - 1; i >= 0; i--) {
      bytes[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    if (v != BigInt.zero) {
      throw ArgumentError('Value does not fit in $length bytes');
    }
    return bytes;
  }
}

class X25519KeyAgreement
    extends KeyAgreement<X25519KeyAgreementParams, X25519PrivateKey> {
  X25519KeyAgreement(X25519PrivateKey key) : super(.x25519(), key);

  @override
  SecretBytes deriveSharedSecret(X25519KeyAgreementParams params) {
    final privateKey = keyMaterial;

    final shared = x25519_impl.X25519(
      privateKey.scalarBytes,
      params.peerPublicKey.uCoordinate,
    );
    return SecretBytes(shared);
  }
}
