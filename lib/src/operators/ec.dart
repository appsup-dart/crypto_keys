import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:crypto_keys/src/algorithms.dart';
import 'package:crypto_keys/src/utils/digest.dart';

import '../utils/pointycastle_ext.dart' as pc;
import '../utils/secure_random.dart';

class EcSigner extends Signer<EcPrivateKey> {
  final pc.Signer _algorithm;
  EcSigner(EcSigningAlgorithm super.algorithm, super.key)
    : _algorithm = algorithm.algorithmImplementation;

  @override
  Signature sign(List<int> data) {
    data = data is Uint8List ? data : Uint8List.fromList(data);
    _algorithm.init(
      true,
      pc.ParametersWithRandom(keyMaterial.keyParameter, DefaultSecureRandom()),
    );

    final sig = _algorithm.generateSignature(data) as pc.ECSignature;
    final length = switch (keyMaterial.curve) {
      Curve.p256 || Curve.p256k => 32,
      Curve.p384 => 48,
      Curve.p521 => 66,
    };
    final bytes = Uint8List(length * 2);
    bytes.setRange(0, length, _bigIntToBytes(sig.r, length).toList().reversed);
    bytes.setRange(
      length,
      length * 2,
      _bigIntToBytes(sig.s, length).toList().reversed,
    );

    return Signature(bytes);
  }
}

class EcVerifier extends Verifier<EcPublicKey> {
  final pc.Signer _algorithm;
  EcVerifier(EcSigningAlgorithm super.algorithm, super.key)
    : _algorithm = algorithm.algorithmImplementation;

  @override
  bool verify(Uint8List data, Signature signature) {
    _algorithm.init(false, keyMaterial.keyParameter);

    final l = signature.data.length ~/ 2;

    return _algorithm.verifySignature(
      data,
      pc.ECSignature(
        _bigIntFromBytes(signature.data.take(l)),
        _bigIntFromBytes(signature.data.skip(l)),
      ),
    );
  }
}

final _b256 = BigInt.from(256);

Iterable<int> _bigIntToBytes(BigInt v, int length) sync* {
  for (var i = 0; i < length; i++) {
    yield (v % _b256).toInt();
    v = v ~/ _b256;
  }
}

BigInt _bigIntFromBytes(Iterable<int> bytes) {
  return bytes.fold(BigInt.zero, (a, b) => a * _b256 + BigInt.from(b));
}

extension on EcSigningAlgorithm {
  pc.Signer get algorithmImplementation => switch (this) {
    EcdsaSigningAlgorithm(:final hash) => pc.ECDSASigner(
      hash.algorithmImplementation,
      null,
    ),
  };
}

pc.ECDomainParameters ecDomainParametersForCurve(Curve curve) =>
    switch (curve) {
      Curve.p256 => pc.ECCurve_secp256r1(),
      Curve.p256k => pc.ECCurve_secp256k1(),
      Curve.p384 => pc.ECCurve_secp384r1(),
      Curve.p521 => pc.ECCurve_secp521r1(),
    };

extension on EcKey {
  pc.ECDomainParameters get ecDomainParameters =>
      ecDomainParametersForCurve(curve);
}

extension on EcPrivateKey {
  pc.AsymmetricKeyParameter get keyParameter =>
      pc.PrivateKeyParameter<pc.ECPrivateKey>(
        pc.ECPrivateKey(eccPrivateKey, ecDomainParameters),
      );
}

extension on EcPublicKey {
  pc.AsymmetricKeyParameter get keyParameter =>
      pc.PublicKeyParameter<pc.ECPublicKey>(
        pc.ECPublicKey(
          ecDomainParameters.curve.createPoint(xCoordinate, yCoordinate),
          ecDomainParameters,
        ),
      );
}
