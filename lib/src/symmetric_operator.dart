part of '../crypto_keys.dart';

class _SymmetricSignerAndVerifier extends Signer<SymmetricKey>
    implements Verifier<SymmetricKey> {
  _SymmetricSignerAndVerifier(Identifier algorithm, SymmetricKey key)
      : super._(algorithm, key);

  @override
  pc.Mac get _algorithm => super._algorithm;

  @override
  Signature sign(List<int> data) {
    data = data is Uint8List ? data : new Uint8List.fromList(data);
    _algorithm.init(new pc.KeyParameter(key.keyValue));
    return new Signature(_algorithm.process(data));
  }

  @override
  bool verify(Uint8List data, Signature signature) => sign(data) == signature;
}

class _SymmetricEncrypter extends Encrypter<SymmetricKey> {
  _SymmetricEncrypter(Identifier algorithm, SymmetricKey key)
      : super._(algorithm, key);

  @override
  pc.BlockCipher get _algorithm => super._algorithm;

  pc.CipherParameters _getParams(
      Uint8List initializationVector, Uint8List additionalAuthenticatedData) {
    var keyParam = new pc.KeyParameter(key.keyValue);

    if (_algorithm is pc.AESKeyWrap) return keyParam;

    var paramsWithIV = new pc.ParametersWithIVAndAad(keyParam,
        initializationVector, additionalAuthenticatedData ?? new Uint8List(0));

    if (_algorithm is pc.PaddedBlockCipher)
      return new pc.PaddedBlockCipherParameters(paramsWithIV, null);

    return paramsWithIV;
  }

  @override
  Uint8List decrypt(EncryptionResult input) {
    _algorithm.init(
        false,
        _getParams(
            input.initializationVector, input.additionalAuthenticatedData));
    var data = input.data;
    if (input.authenticationTag != null) {
      data = new Uint8List(data.length + input.authenticationTag.length);
      data.setAll(0, input.data);
      data.setAll(input.data.length, input.authenticationTag);
    }
    return _algorithm.process(data);
  }

  @override
  EncryptionResult encrypt(Uint8List input,
      {Uint8List initializationVector, Uint8List additionalAuthenticatedData}) {
    initializationVector ??=
        new DefaultSecureRandom().nextBytes(_algorithm.blockSize);

    _algorithm.init(
        true, _getParams(initializationVector, additionalAuthenticatedData));
    var r = _algorithm.process(input);
    var tag;
    if (_algorithm is pc.BlockCipherWithAuthenticationTag) {
      var tagLength =
          (_algorithm as pc.BlockCipherWithAuthenticationTag).tagLength;
      tag =
          new Uint8List.view(r.buffer, r.offsetInBytes + r.length - tagLength);
      r = new Uint8List.view(r.buffer, r.offsetInBytes, r.length - tagLength);
    }

    return new EncryptionResult(r,
        initializationVector:
            _algorithm is pc.AESKeyWrap ? null : initializationVector,
        additionalAuthenticatedData: additionalAuthenticatedData,
        authenticationTag: tag);
  }
}
