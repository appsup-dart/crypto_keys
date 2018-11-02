part of '../crypto_keys.dart';

abstract class _AsymmetricOperator<T extends Key> implements Operator<T> {
  pc.ECDomainParameters get ecDomainParameters {
    var name = (key as EcKey).curve.name.split("/").last;
    switch (name) {
      case "P-256":
        return pc.ECCurve_secp256r1();
      case "P-384":
        return pc.ECCurve_secp384r1();
      case "P-521":
        return pc.ECCurve_secp521r1();
    }
    throw new ArgumentError("Unknwon curve type $name");
  }

  pc.AsymmetricKeyParameter get keyParameter {
    if (key is RsaPrivateKey) {
      var k = key as RsaPrivateKey;
      return new pc.PrivateKeyParameter<pc.RSAPrivateKey>(new pc.RSAPrivateKey(
          k.modulus,
          k.privateExponent,
          k.firstPrimeFactor,
          k.secondPrimeFactor));
    }
    if (key is RsaPublicKey) {
      var k = key as RsaPublicKey;
      return new pc.PublicKeyParameter<pc.RSAPublicKey>(new pc.RSAPublicKey(
        k.modulus,
        k.exponent,
      ));
    }
    var d = ecDomainParameters;

    if (key is EcPrivateKey) {
      var k = key as EcPrivateKey;
      return new pc.PrivateKeyParameter<pc.ECPrivateKey>(new pc.ECPrivateKey(
        k.eccPrivateKey,
        d,
      ));
    }
    if (key is EcPublicKey) {
      var k = key as EcPublicKey;

      return new pc.PublicKeyParameter<pc.ECPublicKey>(new pc.ECPublicKey(
          d.curve.createPoint(k.xCoordinate, k.yCoordinate), d));
    }
    throw new StateError("Unexpected key type ${key}");
  }
}

class _AsymmetricSigner extends Signer<PrivateKey>
    with _AsymmetricOperator<PrivateKey> {
  _AsymmetricSigner(Identifier algorithm, PrivateKey key)
      : super._(algorithm, key);

  @override
  pc.Signer get _algorithm => super._algorithm;

  @override
  Signature sign(List<int> data) {
    data = data is Uint8List ? data : new Uint8List.fromList(data);
    _algorithm.init(true,
        new pc.ParametersWithRandom(keyParameter, new DefaultSecureRandom()));

    if (key is RsaKey) {
      return new Signature(
          (_algorithm.generateSignature(data) as pc.RSASignature).bytes);
    }
    if (key is EcKey) {
      var sig = _algorithm.generateSignature(data) as pc.ECSignature;

      var length =
          (int.parse((key as EcKey).curve.name.split("/").last.substring(2)) /
                  8)
              .ceil();
      var bytes = new Uint8List(length * 2);
      bytes.setRange(
          0, length, _bigIntToBytes(sig.r, length).toList().reversed);
      bytes.setRange(
          length, length * 2, _bigIntToBytes(sig.s, length).toList().reversed);

      return new Signature(bytes);
    }
    throw new UnsupportedError("Unknown key type $key");
  }
}

class _AsymmetricVerifier extends Verifier<PublicKey>
    with _AsymmetricOperator<PublicKey> {
  _AsymmetricVerifier(Identifier algorithm, PublicKey key)
      : super._(algorithm, key);

  @override
  pc.Signer get _algorithm => super._algorithm;

  @override
  bool verify(Uint8List data, Signature signature) {
    if (key is RsaKey) {
      _algorithm.init(false, new pc.ParametersWithRandom(keyParameter, null));
      try {
        return _algorithm.verifySignature(
            data, new pc.RSASignature(signature.data));
      } on ArgumentError {
        return false;
      }
    }
    if (key is EcKey) {
      _algorithm.init(false, keyParameter);

      var l = signature.data.length ~/ 2;

      return _algorithm.verifySignature(
          data,
          new pc.ECSignature(
            _bigIntFromBytes(signature.data.take(l)),
            _bigIntFromBytes(signature.data.skip(l)),
          ));
    }
    throw new UnsupportedError("Unknown key type $key");
  }
}

class _AsymmetricEncrypter extends Encrypter<Key> with _AsymmetricOperator {
  _AsymmetricEncrypter(Identifier algorithm, Key key) : super._(algorithm, key);

  @override
  pc.AsymmetricBlockCipher get _algorithm => super._algorithm;

  @override
  Uint8List decrypt(EncryptionResult input) {
    _algorithm.init(
        false,
        new pc.ParametersWithRandom(
            keyParameter, null //new pc.SecureRandom("Fortuna")
            //..seed(new pc.KeyParameter(new Uint8List(32)))
            ));

    return _algorithm.process(input.data);
  }

  @override
  EncryptionResult encrypt(List<int> input,
      {Uint8List initializationVector, Uint8List additionalAuthenticatedData}) {
    _algorithm.init(true,
        new pc.ParametersWithRandom(keyParameter, new DefaultSecureRandom()));

    return new EncryptionResult(_algorithm.process(input));
  }
}

final _b256 = new BigInt.from(256);

Iterable<int> _bigIntToBytes(BigInt v, int length) sync* {
  for (var i = 0; i < length; i++) {
    yield (v % _b256).toInt();
    v = v ~/ _b256;
  }
}

BigInt _bigIntFromBytes(Iterable<int> bytes) {
  return bytes.fold(BigInt.zero, (a, b) => a * _b256 + new BigInt.from(b));
}
