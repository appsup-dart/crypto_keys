import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:crypto_keys/src/algorithms.dart';
import 'package:crypto_keys/src/digest_utils.dart';

import '../pointycastle_ext.dart' as pc;
import '../secure_random.dart';

class EcSigner extends Signer<EcPrivateKey> {
  final pc.Signer _algorithm;
  EcSigner(EcSigningAlgorithmIdentifier super.algorithm, super.key)
    : _algorithm = algorithm.algorithmImplementation;

  @override
  Signature sign(List<int> data) {
    data = data is Uint8List ? data : Uint8List.fromList(data);
    _algorithm.init(
      true,
      pc.ParametersWithRandom(key.keyParameter, DefaultSecureRandom()),
    );

    final sig = _algorithm.generateSignature(data) as pc.ECSignature;
    final length = {
      CurveIdentifier.p256: 32,
      CurveIdentifier.p256k: 32,
      CurveIdentifier.p384: 48,
      CurveIdentifier.p521: 66,
    }[key.curve]!;
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
  EcVerifier(EcSigningAlgorithmIdentifier super.algorithm, super.key)
    : _algorithm = algorithm.algorithmImplementation;

  @override
  bool verify(Uint8List data, Signature signature) {
    _algorithm.init(false, key.keyParameter);

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

extension on EcSigningAlgorithmIdentifier {
  pc.Signer get algorithmImplementation => switch (this) {
    EcdsaSigningAlgorithmIdentifier(:final hash) => pc.ECDSASigner(
      hash.algorithmImplementation,
      null,
    ),
  };
}

pc.ECDomainParameters ecDomainParametersForCurve(CurveIdentifier curve) {
  final name = curve.name.split('/').last;
  switch (name) {
    case 'P-256':
      return pc.ECCurve_secp256r1();
    case 'P-256K':
      return pc.ECCurve_secp256k1();
    case 'P-384':
      return pc.ECCurve_secp384r1();
    case 'P-521':
      return pc.ECCurve_secp521r1();
  }
  throw ArgumentError('Unknwon curve type $name');
}

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
