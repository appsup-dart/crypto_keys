import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:crypto_keys/src/algorithms.dart';
import 'package:crypto_keys/src/digest_utils.dart';

import '../pointycastle_ext.dart' as pc;
import '../secure_random.dart';

class SymmetricSignerAndVerifier extends Signer<SymmetricKey>
    implements Verifier<SymmetricKey> {
  final pc.Mac _algorithm;
  SymmetricSignerAndVerifier(
    SymmetricSigningAlgorithm super.algorithm,
    super.key,
  ) : _algorithm = algorithm.algorithmImplementation;

  @override
  Signature sign(List<int> data) {
    data = data is Uint8List ? data : Uint8List.fromList(data);
    _algorithm.init(pc.KeyParameter(keyMaterial.keyValue));
    return Signature(_algorithm.process(data));
  }

  @override
  bool verify(Uint8List data, Signature signature) => sign(data) == signature;
}

extension on SymmetricSigningAlgorithm {
  pc.Mac get algorithmImplementation => switch (this) {
    HmacSigningAlgorithm(:final hash) => pc.HMac(
      hash.algorithmImplementation,
      hash.blockLength,
    ),
  };
}

abstract class SymmetricCipherOperator extends Encrypter<SymmetricKey>
    implements Decrypter<SymmetricKey> {
  factory SymmetricCipherOperator(
    SymmetricEncryptionAlgorithm algorithm,
    SymmetricKey key,
  ) => switch (algorithm) {
    AesKeyWrapEncryptionAlgorithm() => _KeyWrapSymmetricCipherOperator(
      algorithm,
      key,
    ),
    AesGcmEncryptionAlgorithm() => _GcmSymmetricCipherOperator(algorithm, key),
    AesEaxEncryptionAlgorithm() => _AeadSymmetricCipherOperator._eax(
      algorithm,
      key,
    ),
    ChaCha20Poly1305EncryptionAlgorithm() =>
      _AeadSymmetricCipherOperator._chacha(algorithm, key),
    AesCbcPkcs7EncryptionAlgorithm() => _PaddedOrBlockSymmetricCipherOperator(
      algorithm,
      key,
    ),
    AesCbcPkcs7HmacEncryptionAlgorithm() =>
      _TaggingBlockSymmetricCipherOperator(algorithm, key),
  };

  SymmetricCipherOperator._base(super.algorithm, super.key);

  pc.KeyParameter get _keyParam => pc.KeyParameter(keyMaterial.keyValue);
}

class _AeadSymmetricCipherOperator extends SymmetricCipherOperator {
  final pc.AEADCipher _cipher;
  final int _ivLength;

  _AeadSymmetricCipherOperator._eax(
    AesEaxEncryptionAlgorithm super.algorithm,
    super.key,
  ) : _cipher = pc.AEADCipher('AES/EAX'),
      _ivLength = 16,
      super._base();

  _AeadSymmetricCipherOperator._chacha(
    ChaCha20Poly1305EncryptionAlgorithm super.algorithm,
    super.key,
  ) : _cipher = pc.ChaCha20Poly1305(pc.ChaCha7539Engine(), pc.Poly1305()),
      _ivLength = 12,
      super._base();

  pc.AEADParameters _params(
    Uint8List initializationVector,
    Uint8List? additionalAuthenticatedData,
  ) => pc.AEADParameters(
    _keyParam,
    128,
    initializationVector,
    additionalAuthenticatedData ?? Uint8List(0),
  );

  Uint8List _process(Uint8List input) {
    final output = Uint8List(_cipher.getOutputSize(input.length));
    var outputLength = _cipher.processBytes(input, 0, input.length, output, 0);
    outputLength += _cipher.doFinal(output, outputLength);
    return Uint8List.sublistView(output, 0, outputLength);
  }

  @override
  Uint8List decrypt(EncryptionResult input) {
    _cipher.init(
      false,
      _params(input.initializationVector!, input.additionalAuthenticatedData),
    );
    final tag = input.authenticationTag ?? Uint8List(0);
    final data = Uint8List(input.data.length + tag.length)
      ..setAll(0, input.data)
      ..setAll(input.data.length, tag);
    return _process(data);
  }

  @override
  EncryptionResult encrypt(
    Uint8List input, {
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  }) {
    initializationVector ??= DefaultSecureRandom().nextBytes(_ivLength);

    _cipher.init(
      true,
      _params(initializationVector, additionalAuthenticatedData),
    );
    var out = _process(input);
    final tagLength = _cipher.mac.length;
    final tag = Uint8List.view(
      out.buffer,
      out.offsetInBytes + out.length - tagLength,
      tagLength,
    );
    out = Uint8List.view(out.buffer, out.offsetInBytes, out.length - tagLength);

    return EncryptionResult(
      out,
      initializationVector: initializationVector,
      additionalAuthenticatedData: additionalAuthenticatedData,
      authenticationTag: tag,
    );
  }
}

class _GcmSymmetricCipherOperator extends SymmetricCipherOperator {
  final pc.GCMBlockCipher _cipher;

  _GcmSymmetricCipherOperator(
    AesGcmEncryptionAlgorithm super.algorithm,
    super.key,
  ) : _cipher = pc.GCMBlockCipher(pc.AESEngine()),
      super._base();

  pc.AEADParameters _params(
    Uint8List initializationVector,
    Uint8List? additionalAuthenticatedData,
  ) => pc.AEADParameters(
    _keyParam,
    128,
    initializationVector,
    additionalAuthenticatedData ?? Uint8List(0),
  );

  Uint8List _process(Uint8List input) {
    final output = Uint8List(_cipher.getOutputSize(input.length));
    var outputLength = _cipher.processBytes(input, 0, input.length, output, 0);
    outputLength += _cipher.doFinal(output, outputLength);
    return Uint8List.sublistView(output, 0, outputLength);
  }

  @override
  Uint8List decrypt(EncryptionResult input) {
    _cipher.init(
      false,
      _params(input.initializationVector!, input.additionalAuthenticatedData),
    );
    final tag = input.authenticationTag ?? Uint8List(0);
    final data = Uint8List(input.data.length + tag.length)
      ..setAll(0, input.data)
      ..setAll(input.data.length, tag);
    return _process(data);
  }

  @override
  EncryptionResult encrypt(
    Uint8List input, {
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  }) {
    initializationVector ??= DefaultSecureRandom().nextBytes(16);
    _cipher.init(
      true,
      _params(initializationVector, additionalAuthenticatedData),
    );
    var out = _process(input);
    const tagLength = 16;
    final tag = Uint8List.view(
      out.buffer,
      out.offsetInBytes + out.length - tagLength,
      tagLength,
    );
    out = Uint8List.view(out.buffer, out.offsetInBytes, out.length - tagLength);

    return EncryptionResult(
      out,
      initializationVector: initializationVector,
      additionalAuthenticatedData: additionalAuthenticatedData,
      authenticationTag: tag,
    );
  }
}

class _KeyWrapSymmetricCipherOperator extends SymmetricCipherOperator {
  final pc.AESKeyWrap _cipher;

  _KeyWrapSymmetricCipherOperator(
    AesKeyWrapEncryptionAlgorithm super.algorithm,
    super.key,
  ) : _cipher = pc.AESKeyWrap(),
      super._base();

  @override
  Uint8List decrypt(EncryptionResult input) {
    _cipher.init(false, _keyParam);
    return _cipher.process(input.data);
  }

  @override
  EncryptionResult encrypt(
    Uint8List input, {
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  }) {
    _cipher.init(true, _keyParam);
    return EncryptionResult(
      _cipher.process(input),
      initializationVector: null,
      additionalAuthenticatedData: additionalAuthenticatedData,
    );
  }
}

class _PaddedOrBlockSymmetricCipherOperator extends SymmetricCipherOperator {
  final pc.PaddedBlockCipher _cipher;

  _PaddedOrBlockSymmetricCipherOperator(
    AesCbcPkcs7EncryptionAlgorithm super.algorithm,
    super.key,
  ) : _cipher = pc.PaddedBlockCipherImpl(
        pc.PKCS7Padding(),
        pc.CBCBlockCipher(pc.AESEngine()),
      ),
      super._base();

  pc.CipherParameters _params(
    Uint8List initializationVector,
    Uint8List? additionalAuthenticatedData,
  ) {
    final paramsWithIV = pc.ParametersWithIVAndAad(
      _keyParam,
      initializationVector,
      additionalAuthenticatedData ?? Uint8List(0),
    );
    return pc.PaddedBlockCipherParameters(paramsWithIV, null);
  }

  Uint8List _process(Uint8List input) => _cipher.process(input);

  void _init(bool forEncryption, pc.CipherParameters params) {
    _cipher.init(forEncryption, params);
  }

  @override
  Uint8List decrypt(EncryptionResult input) {
    _init(
      false,
      _params(input.initializationVector!, input.additionalAuthenticatedData),
    );
    return _process(input.data);
  }

  @override
  EncryptionResult encrypt(
    Uint8List input, {
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  }) {
    initializationVector ??= DefaultSecureRandom().nextBytes(_cipher.blockSize);
    _init(true, _params(initializationVector, additionalAuthenticatedData));
    return EncryptionResult(
      _process(input),
      initializationVector: initializationVector,
      additionalAuthenticatedData: additionalAuthenticatedData,
    );
  }
}

class _TaggingBlockSymmetricCipherOperator extends SymmetricCipherOperator {
  final pc.BlockCipherWithAuthenticationTag _cipher;

  _TaggingBlockSymmetricCipherOperator(
    AesCbcPkcs7HmacEncryptionAlgorithm super.algorithm,
    super.key,
  ) : _cipher = pc.AesCbcAuthenticatedCipherWithHash(
        pc.HMac(
          algorithm.hash.algorithmImplementation,
          algorithm.hash.blockLength,
        ),
      ),
      super._base();

  pc.ParametersWithIVAndAad _params(
    Uint8List initializationVector,
    Uint8List? additionalAuthenticatedData,
  ) => pc.ParametersWithIVAndAad(
    _keyParam,
    initializationVector,
    additionalAuthenticatedData ?? Uint8List(0),
  );

  @override
  Uint8List decrypt(EncryptionResult input) {
    _cipher.init(
      false,
      _params(input.initializationVector!, input.additionalAuthenticatedData),
    );
    final tag = input.authenticationTag ?? Uint8List(0);
    final data = Uint8List(input.data.length + tag.length)
      ..setAll(0, input.data)
      ..setAll(input.data.length, tag);
    return _cipher.process(data);
  }

  @override
  EncryptionResult encrypt(
    Uint8List input, {
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  }) {
    final ivLength = _cipher.blockSize;
    initializationVector ??= DefaultSecureRandom().nextBytes(ivLength);
    _cipher.init(
      true,
      _params(initializationVector, additionalAuthenticatedData),
    );
    var out = _cipher.process(input);
    final tagLength = _cipher.tagLength;
    final tag = Uint8List.view(
      out.buffer,
      out.offsetInBytes + out.length - tagLength,
      tagLength,
    );
    out = Uint8List.view(out.buffer, out.offsetInBytes, out.length - tagLength);
    return EncryptionResult(
      out,
      initializationVector: initializationVector,
      additionalAuthenticatedData: additionalAuthenticatedData,
      authenticationTag: tag,
    );
  }
}
