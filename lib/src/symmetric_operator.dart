part of '../crypto_keys.dart';

class _SymmetricSignerAndVerifier extends Signer<SymmetricKey>
    implements Verifier<SymmetricKey> {
  _SymmetricSignerAndVerifier(super.algorithm, super.key) : super._();

  @override
  pc.Mac get _algorithm => super._algorithm as pc.Mac;

  @override
  Signature sign(List<int> data) {
    data = data is Uint8List ? data : Uint8List.fromList(data);
    _algorithm.init(pc.KeyParameter(key.keyValue));
    return Signature(_algorithm.process(data));
  }

  @override
  bool verify(Uint8List data, Signature signature) => sign(data) == signature;
}

class _SymmetricEncrypter extends Encrypter<SymmetricKey>
    implements Decrypter<SymmetricKey> {
  _SymmetricEncrypter(super.algorithm, super.key) : super._();

  pc.CipherParameters _getParams(
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  ) {
    var keyParam = pc.KeyParameter(key.keyValue);

    if (super._algorithm is pc.AESKeyWrap) return keyParam;
    if (super._algorithm is pc.GCMBlockCipher ||
        super._algorithm is pc.AEADCipher) {
      return pc.AEADParameters(
        keyParam,
        128,
        initializationVector!,
        additionalAuthenticatedData ?? Uint8List(0),
      );
    }

    var paramsWithIV = pc.ParametersWithIVAndAad(
      keyParam,
      initializationVector!,
      additionalAuthenticatedData ?? Uint8List(0),
    );

    if (super._algorithm is pc.PaddedBlockCipher) {
      return pc.PaddedBlockCipherParameters(paramsWithIV, null);
    }

    return paramsWithIV;
  }

  Uint8List _process(Uint8List input) {
    if (super._algorithm case final pc.AEADCipher aeadCipher) {
      var output = Uint8List(aeadCipher.getOutputSize(input.length));
      var outputLength = aeadCipher.processBytes(
        input,
        0,
        input.length,
        output,
        0,
      );
      outputLength += aeadCipher.doFinal(output, outputLength);
      return Uint8List.sublistView(output, 0, outputLength);
    }

    return (super._algorithm as dynamic).process(input) as Uint8List;
  }

  void _init(bool forEncryption, pc.CipherParameters params) {
    if (super._algorithm is pc.AEADCipher) {
      (super._algorithm as pc.AEADCipher).init(forEncryption, params);
      return;
    }
    if (super._algorithm is pc.PaddedBlockCipher) {
      (super._algorithm as pc.PaddedBlockCipher).init(forEncryption, params);
      return;
    }
    if (super._algorithm is pc.BlockCipher) {
      (super._algorithm as pc.BlockCipher).init(forEncryption, params);
      return;
    }
    throw UnsupportedError(
      'Unsupported symmetric cipher type: ${super._algorithm.runtimeType}',
    );
  }

  @override
  Uint8List decrypt(EncryptionResult input) {
    _init(
      false,
      _getParams(input.initializationVector, input.additionalAuthenticatedData),
    );
    var data = input.data;
    if (input.authenticationTag != null) {
      data = Uint8List(data.length + input.authenticationTag!.length);
      data.setAll(0, input.data);
      data.setAll(input.data.length, input.authenticationTag!);
    }
    return _process(data);
  }

  @override
  EncryptionResult encrypt(
    Uint8List input, {
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  }) {
    initializationVector ??= DefaultSecureRandom().nextBytes(
      super._algorithm is pc.ChaCha20Poly1305
          ? 12
          : super._algorithm is pc.BlockCipher
          ? (super._algorithm as pc.BlockCipher).blockSize
          : 16,
    );

    _init(true, _getParams(initializationVector, additionalAuthenticatedData));
    var r = _process(input);
    Uint8List? tag;
    if (super._algorithm is pc.GCMBlockCipher ||
        super._algorithm is pc.AEADCipher) {
      var tagLength = 16;
      if (super._algorithm is pc.AEADCipher) {
        tagLength = (super._algorithm as pc.AEADCipher).mac.length;
      }
      tag = Uint8List.view(
        r.buffer,
        r.offsetInBytes + r.length - tagLength,
        tagLength,
      );
      r = Uint8List.view(r.buffer, r.offsetInBytes, r.length - tagLength);
    }
    if (super._algorithm is pc.BlockCipherWithAuthenticationTag) {
      var tagLength =
          (super._algorithm as pc.BlockCipherWithAuthenticationTag).tagLength;
      tag = Uint8List.view(
        r.buffer,
        r.offsetInBytes + r.length - tagLength,
        tagLength,
      );
      r = Uint8List.view(r.buffer, r.offsetInBytes, r.length - tagLength);
    }

    return EncryptionResult(
      r,
      initializationVector: super._algorithm is pc.AESKeyWrap
          ? null
          : initializationVector,
      additionalAuthenticatedData: additionalAuthenticatedData,
      authenticationTag: tag,
    );
  }
}
