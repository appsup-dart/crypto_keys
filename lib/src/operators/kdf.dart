import 'dart:typed_data';

import '../../crypto_keys.dart';
import '../utils/digest.dart';
import '../utils/pointycastle_ext.dart' as pc;

abstract class Kdf<T extends KdfParams, K extends KeyMaterial>
    extends Operator<K> {
  Kdf(KdfAlgorithm super.algorithm, super.key);

  Uint8List deriveKey(T params);
}

abstract class PasswordKdf<T extends PasswordKdfParams>
    extends Kdf<T, Password> {
  PasswordKdf(PasswordKdfAlgorithm super.algorithm, super.key);
}

abstract class SecretBytesKdf<T extends SecretBytesKdfParams>
    extends Kdf<T, SecretBytes> {
  SecretBytesKdf(SecretKdfAlgorithm super.algorithm, super.key) {
    if (keyMaterial.value.isEmpty) {
      throw ArgumentError.value(
        keyMaterial.value,
        'key',
        'Secret bytes must not be empty',
      );
    }
  }
}

class ConcatKdf extends SecretBytesKdf<ConcatKdfKdfParams> {
  ConcatKdf(DigestAlgorithm hash, SecretBytes key)
    : super(ConcatKdfAlgorithm(hash), key);

  /// Derives key material from shared secret and caller-provided `otherInfo`.
  @override
  Uint8List deriveKey(ConcatKdfKdfParams params) {
    if (params.hash == DigestAlgorithm.sha1) {
      throw UnsupportedError(
        'ConcatKDF supports SHA-256, SHA-384 and SHA-512 only',
      );
    }
    final sharedSecret = keyMaterial.value;

    final keyBitLength = params.keyBitLength;

    final otherInfo = params.otherInfo ?? Uint8List(0);

    final selectedDigest = params.hash.algorithmImplementation;

    if (keyBitLength <= 0) {
      throw ArgumentError.value(
        keyBitLength,
        'keyBitLength',
        'Must be greater than 0',
      );
    }
    if (sharedSecret.isEmpty) {
      throw ArgumentError.value(
        sharedSecret,
        'sharedSecret',
        'Shared secret must not be empty',
      );
    }

    final hashLen = selectedDigest.digestSize;
    final reps = (keyBitLength + hashLen * 8 - 1) ~/ (hashLen * 8);
    final output = BytesBuilder(copy: false);

    for (var counter = 1; counter <= reps; counter++) {
      final ctr = Uint8List(4)..buffer.asByteData().setUint32(0, counter);
      selectedDigest.reset();
      selectedDigest.update(ctr, 0, ctr.length);
      selectedDigest.update(sharedSecret, 0, sharedSecret.length);
      selectedDigest.update(otherInfo, 0, otherInfo.length);
      final roundOutput = Uint8List(hashLen);
      selectedDigest.doFinal(roundOutput, 0);
      output.add(roundOutput);
    }

    final keyLen = (keyBitLength + 7) ~/ 8;
    return Uint8List.fromList(output.toBytes().take(keyLen).toList());
  }
}

class Argon2id extends PasswordKdf<Argon2idKdfParams> {
  Argon2id(Password key) : super(const Argon2idKdfAlgorithm(), key);

  @override
  Uint8List deriveKey(Argon2idKdfParams params) {
    final password = keyMaterial;
    if (params.salt.length < 8) {
      throw ArgumentError.value(
        params.salt,
        'salt',
        'Argon2 requires a salt of at least 8 bytes',
      );
    }
    if (params.iterations < 1) {
      throw ArgumentError.value(
        params.iterations,
        'iterations',
        'Must be at least 1',
      );
    }
    if (params.keyBitLength <= 0) {
      throw ArgumentError.value(
        params.keyBitLength,
        'keyBitLength',
        'Must be greater than 0',
      );
    }
    if (params.memoryKiB < 2 * params.lanes) {
      throw ArgumentError.value(
        params.memoryKiB,
        'memoryKiB',
        'Argon2 memory must be at least 2 * lanes (${2 * params.lanes} KiB)',
      );
    }
    final keyLength = (params.keyBitLength + 7) ~/ 8;
    final gen = pc.Argon2BytesGenerator()
      ..init(
        pc.Argon2Parameters(
          pc.Argon2Parameters.ARGON2_id,
          params.salt,
          desiredKeyLength: keyLength,
          iterations: params.iterations,
          memory: params.memoryKiB,
          lanes: params.lanes,
          version: pc.Argon2Parameters.ARGON2_VERSION_13,
          secret: params.secret,
          additional: params.additionalData,
        ),
      );
    return gen.process(password.value);
  }
}

class Pbkdf2 extends PasswordKdf<Pbkdf2KdfParams> {
  Pbkdf2(DigestAlgorithm hash, Password key)
    : super(Pbkdf2KdfAlgorithm(hash), key);

  @override
  Uint8List deriveKey(Pbkdf2KdfParams params) {
    assert(params.hash == (this.algorithm as Pbkdf2KdfAlgorithm).hash);
    final password = keyMaterial;

    final salt = params.salt;
    final iterations = params.iterations;
    final keyBitLength = params.keyBitLength;
    if (salt.isEmpty) {
      throw ArgumentError.value(salt, 'salt', 'Salt must not be empty');
    }
    if (iterations <= 0) {
      throw ArgumentError.value(
        iterations,
        'iterations',
        'Must be greater than 0',
      );
    }
    if (keyBitLength <= 0) {
      throw ArgumentError.value(
        keyBitLength,
        'keyBitLength',
        'Must be greater than 0',
      );
    }
    final keyLength = (keyBitLength + 7) ~/ 8;
    final algorithm = pc.PBKDF2KeyDerivator(
      pc.HMac(params.hash.algorithmImplementation, params.hash.blockLength),
    );
    algorithm.init(pc.Pbkdf2Parameters(salt, iterations, keyLength));
    return algorithm.process(password.value);
  }
}

class Hkdf extends SecretBytesKdf<HkdfKdfParams> {
  Hkdf(DigestAlgorithm hash, SecretBytes key)
    : super(HkdfKdfAlgorithm(hash), key);

  @override
  Uint8List deriveKey(HkdfKdfParams params) {
    final secret = keyMaterial;
    if (secret.value.isEmpty) {
      throw ArgumentError.value(
        secret.value,
        'key',
        'Secret bytes must not be empty',
      );
    }
    if (params.keyBitLength <= 0) {
      throw ArgumentError.value(
        params.keyBitLength,
        'keyBitLength',
        'Must be greater than 0',
      );
    }
    if (params.hash == DigestAlgorithm.sha1) {
      throw UnsupportedError('HKDF supports SHA-256, SHA-384 and SHA-512 only');
    }
    final keyLength = (params.keyBitLength + 7) ~/ 8;
    final algorithm = pc.HKDFKeyDerivator(params.hash.algorithmImplementation);
    algorithm.init(
      pc.HkdfParameters(
        secret.value,
        keyLength,
        params.salt,
        params.info ?? Uint8List(0),
      ),
    );
    return algorithm.process(Uint8List(0));
  }
}
