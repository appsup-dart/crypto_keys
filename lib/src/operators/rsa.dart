import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:crypto_keys/src/algorithms.dart';
import 'package:crypto_keys/src/utils/digest.dart';
import '../utils/pointycastle_ext.dart' as pc;
import '../utils/secure_random.dart';

class RsaSigner extends Signer<RsaPrivateKey> {
  final pc.Signer _algorithm;

  RsaSigner(RsaSigningAlgorithm super.algorithm, super.key)
    : _algorithm = algorithm.algorithmImplementation;

  @override
  Signature sign(List<int> data) {
    data = data is Uint8List ? data : Uint8List.fromList(data);
    _algorithm.init(
      true,
      pc.ParametersWithRandom(keyMaterial.keyParameter, DefaultSecureRandom()),
    );

    final signature = _algorithm.generateSignature(data);
    if (signature is pc.RSASignature) {
      return Signature(signature.bytes);
    }
    if (signature is pc.PSSSignature) {
      return Signature(signature.bytes);
    }
    throw UnsupportedError(
      'Unknown RSA signature type ${signature.runtimeType}',
    );
  }
}

class RsaVerifier extends Verifier<RsaPublicKey> {
  final pc.Signer _algorithm;
  RsaVerifier(RsaSigningAlgorithm super.algorithm, super.key)
    : _algorithm = algorithm.algorithmImplementation,
      super();

  @override
  bool verify(Uint8List data, Signature signature) {
    _algorithm.init(
      false,
      pc.ParametersWithRandom(
        keyMaterial.keyParameter,
        pc.SecureRandom('Fortuna'),
      ),
    );
    try {
      final rsaSignature = _algorithm is pc.PSSSigner
          ? pc.PSSSignature(signature.data)
          : pc.RSASignature(signature.data);
      return _algorithm.verifySignature(data, rsaSignature);
    } on ArgumentError {
      return false;
    }
  }
}

class RsaEncrypter extends Encrypter<RsaPublicKey> {
  final pc.AsymmetricBlockCipher _algorithm;
  RsaEncrypter(RsaEncryptionAlgorithm super.algorithm, super.key)
    : _algorithm = algorithm.algorithmImplementation;

  @override
  EncryptionResult encrypt(
    List<int> input, {
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  }) {
    _algorithm.init(
      true,
      pc.ParametersWithRandom(keyMaterial.keyParameter, DefaultSecureRandom()),
    );

    return EncryptionResult(_algorithm.process(input as Uint8List));
  }
}

class RsaDecrypter extends Decrypter<RsaPrivateKey> {
  final pc.AsymmetricBlockCipher _algorithm;
  RsaDecrypter(RsaEncryptionAlgorithm super.algorithm, super.key)
    : _algorithm = algorithm.algorithmImplementation;

  @override
  Uint8List decrypt(EncryptionResult input) {
    _algorithm.init(
      false,
      pc.ParametersWithRandom(
        keyMaterial.keyParameter,
        pc.SecureRandom('Fortuna'),
      ),
    );

    return _algorithm.process(input.data);
  }
}

extension on RsaEncryptionAlgorithm {
  pc.AsymmetricBlockCipher get algorithmImplementation => switch (this) {
    RsaPkcs1EncryptionAlgorithm() => pc.PKCS1Encoding(pc.RSAEngine()),
    RsaOaepSha1EncryptionAlgorithm() => pc.OAEPEncoding.withSHA1(
      pc.RSAEngine(),
    ),
    RsaOaepSha256EncryptionAlgorithm() => pc.OAEPEncoding.withSHA256(
      pc.RSAEngine(),
    ),
  };
}

extension on RsaSigningAlgorithm {
  pc.Signer get algorithmImplementation => switch (this) {
    RsaPkcs1SigningAlgorithm(:final hash) => pc.RSASigner(
      hash.algorithmImplementation,
      hash.rsaPkcs1DigestIdentifierHex,
    ),
    RsaPssSigningAlgorithm(
      :final sigHash,
      :final mgf1Hash,
      :final saltLength,
    ) =>
      pc.PssSignerAdapter(
        sigDigest: sigHash.algorithmImplementation,
        mgf1Digest: mgf1Hash.algorithmImplementation,
        saltLength: saltLength,
      ),
  };
}

extension on RsaPrivateKey {
  pc.AsymmetricKeyParameter get keyParameter {
    return pc.PrivateKeyParameter<pc.RSAPrivateKey>(
      pc.RSAPrivateKey(
        modulus,
        privateExponent,
        firstPrimeFactor,
        secondPrimeFactor,
      ),
    );
  }
}

extension on RsaPublicKey {
  pc.AsymmetricKeyParameter get keyParameter {
    return pc.PublicKeyParameter<pc.RSAPublicKey>(
      pc.RSAPublicKey(modulus, exponent),
    );
  }
}
