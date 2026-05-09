part of '../crypto_keys.dart';

final _ecdh = _Ecdh();

final _concatKdf = _ConcatKdf();

/// Generic ECDH shared-secret derivation helpers.
///
/// These helpers derive the ECDH shared secret from EC key pairs.
class _Ecdh {
  const _Ecdh();

  /// Derives the ECDH shared secret for the given EC key pair.
  ///
  /// The input keys must both be EC keys and use the same curve (`P-256`,
  /// `P-384`, or `P-521`). The output is fixed-length, big-endian bytes.
  Uint8List deriveSharedSecret({
    required EcPrivateKey privateKey,
    required EcPublicKey publicKey,
  }) {
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
    return _encodeBigIntFixedWidth(zInt, agreement.getFieldSize());
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

/// Generic Concat KDF (NIST SP 800-56A Section 5.8.1).
class _ConcatKdf {
  const _ConcatKdf();

  /// Derives key material from shared secret and caller-provided `otherInfo`.
  Uint8List deriveKey({
    required Uint8List sharedSecret,
    required Uint8List otherInfo,
    required int keyBitLength,
    DigestAlgorithm? hash,
    pc.Digest? digest,
  }) {
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

    final selectedDigest = digest ?? (hash ?? .sha256).algorithmImplementation;
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

SecretBytes _deriveEcdhSharedSecret({
  required EcPrivateKey privateKey,
  required EcdhKeyDeriverParams params,
}) {
  final peerPublicKey = params.peerPublicKey;
  final privateEc = privateKey;
  final peerEc = peerPublicKey;
  if (privateEc.curve != peerEc.curve) {
    throw ArgumentError(
      'ECDH requires matching curves, got '
      '${privateEc.curve.name} and ${peerEc.curve.name}',
    );
  }
  return SecretBytes(
    _ecdh.deriveSharedSecret(privateKey: privateEc, publicKey: peerEc),
  );
}

Uint8List _deriveArgon2idBits({
  required Password password,
  required Argon2idKeyDeriverParams params,
}) {
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

Uint8List _derivePbkdf2Bits({
  required Password password,
  required Pbkdf2KeyDeriverParams params,
}) {
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

Uint8List _deriveHkdfBits({
  required SecretBytes secret,
  required HkdfKeyDeriverParams params,
}) {
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
  _ensureSupportsHkdf(params.hash);
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

Uint8List _deriveConcatKdfBits({
  required SecretBytes secret,
  required ConcatKdfKeyDeriverParams params,
}) {
  if (secret.value.isEmpty) {
    throw ArgumentError.value(
      secret.value,
      'key',
      'Secret bytes must not be empty',
    );
  }
  _ensureSupportsConcatKdf(params.hash);
  return _concatKdf.deriveKey(
    sharedSecret: secret.value,
    otherInfo: params.otherInfo ?? Uint8List(0),
    keyBitLength: params.keyBitLength,
    digest: params.hash.algorithmImplementation,
  );
}

void _ensureSupportsHkdf(DigestAlgorithm hash) {
  if (hash == DigestAlgorithm.sha1) {
    throw UnsupportedError('HKDF supports SHA-256, SHA-384 and SHA-512 only');
  }
}

void _ensureSupportsConcatKdf(DigestAlgorithm hash) {
  if (hash == DigestAlgorithm.sha1) {
    throw UnsupportedError(
      'ConcatKDF supports SHA-256, SHA-384 and SHA-512 only',
    );
  }
}
