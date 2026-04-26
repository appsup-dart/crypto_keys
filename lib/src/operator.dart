part of '../crypto_keys.dart';

/// Base class for cryptographic operations
abstract class Operator<T extends KeyMaterial> {
  /// The key material used for this operation
  final T key;

  /// The algorithm used for this operation
  final AlgorithmIdentifier algorithm;

  final pc.Algorithm _algorithm;

  Operator._(this.algorithm, this.key)
      : _algorithm = algorithm.createAlgorithm();
}

/// Marker base class for key derivation parameter objects.
sealed class KeyDeriverParams {
  const KeyDeriverParams();

  /// Shorthand factory for [EcdhKeyDeriverParams].
  static EcdhKeyDeriverParams ecdh(
          {required PublicKey peerPublicKey}) =>
      EcdhKeyDeriverParams(peerPublicKey: peerPublicKey);

  /// Shorthand factory for [Pbkdf2KeyDeriverParams].
  static Pbkdf2KeyDeriverParams pbkdf2(
          {required Uint8List salt,
          required int iterations,
          required int keyBitLength}) =>
      Pbkdf2KeyDeriverParams(
          salt: salt, iterations: iterations, keyBitLength: keyBitLength);

  /// Shorthand factory for [HkdfKeyDeriverParams].
  static HkdfKeyDeriverParams hkdf(
          {required Uint8List salt,
          required int keyBitLength,
          Uint8List? info}) =>
      HkdfKeyDeriverParams(salt: salt, keyBitLength: keyBitLength, info: info);

  /// Shorthand factory for [ConcatKdfKeyDeriverParams].
  static ConcatKdfKeyDeriverParams concatKdf(
          {required int keyBitLength, Uint8List? otherInfo}) =>
      ConcatKdfKeyDeriverParams(
          keyBitLength: keyBitLength, otherInfo: otherInfo);
}

/// Parameters for ECDH + Concat KDF derivation.
class EcdhKeyDeriverParams extends KeyDeriverParams {
  final PublicKey peerPublicKey;

  const EcdhKeyDeriverParams({required this.peerPublicKey});
}

/// Parameters for PBKDF2 key derivation.
class Pbkdf2KeyDeriverParams extends KeyDeriverParams {
  final Uint8List salt;
  final int iterations;
  final int keyBitLength;

  const Pbkdf2KeyDeriverParams(
      {required this.salt,
      required this.iterations,
      required this.keyBitLength});
}

/// Parameters for HKDF key derivation.
class HkdfKeyDeriverParams extends KeyDeriverParams {
  final Uint8List salt;
  final Uint8List? info;
  final int keyBitLength;

  const HkdfKeyDeriverParams(
      {required this.salt, this.info, required this.keyBitLength});
}

/// Parameters for Concat KDF key derivation.
class ConcatKdfKeyDeriverParams extends KeyDeriverParams {
  final int keyBitLength;
  final Uint8List? otherInfo;

  const ConcatKdfKeyDeriverParams(
      {required this.keyBitLength, this.otherInfo});
}

/// Operator for signing
abstract class Signer<T extends PrivateKey> extends Operator<T> {
  Signer._(Identifier algorithm, T key)
      : super._(algorithm as AlgorithmIdentifier<pc.Algorithm>, key);

  /// Signs the input [data] using the [key] and [algorithm]
  Signature sign(List<int> data);
}

/// Operator for verifying a signature
abstract class Verifier<T extends PublicKey> extends Operator<T> {
  Verifier._(Identifier algorithm, T key)
      : super._(algorithm as AlgorithmIdentifier<pc.Algorithm>, key);

  /// Verifies that [signature] is a valid signature for the input [data] using
  /// the [key] and [algorithm]
  bool verify(Uint8List data, Signature signature);
}

/// Operator for deriving shared key material from a private/public key pair.
///
/// The local private key is [Operator.key]. The peer public key is provided per
/// derivation call to support deriving with multiple peers using one operator.
abstract class KeyDeriver<T extends KeyMaterial, P extends KeyDeriverParams>
    extends Operator<T> {
  KeyDeriver._(Identifier algorithm, T keyMaterial)
      : super._(algorithm as AlgorithmIdentifier<pc.Algorithm>, keyMaterial);

  /// Derives key material using algorithm-specific [params].
  Uint8List deriveKey(P params);
}

/// Represents the result of signing some data
abstract class Signature {
  /// Byte representation of the signature
  Uint8List get data;

  factory Signature(Uint8List data) = SignatureImpl;
}

/// Operator for encrypting and decrypting data
abstract class Encrypter<T extends Key> extends Operator<T> {
  Encrypter._(Identifier algorithm, T key)
      : super._(algorithm as AlgorithmIdentifier<pc.Algorithm>, key);

  /// Encrypts the input data using the [key] and [algorithm]
  ///
  /// When the algorithm requires an initialization vector and none is provided,
  /// a random initialization vector is generated.
  EncryptionResult encrypt(Uint8List input,
      {Uint8List? initializationVector,
      Uint8List? additionalAuthenticatedData});

  /// Decrypts the input data using the [key] and [algorithm]
  Uint8List decrypt(EncryptionResult input);
}

/// Represents the result of encrypting some data
abstract class EncryptionResult {
  /// Byte representation of the ciphertext
  Uint8List get data;

  /// The initialization vector used for encrypting when required by the
  /// algorithm
  Uint8List? get initializationVector;

  Uint8List? get authenticationTag;

  Uint8List? get additionalAuthenticatedData;

  factory EncryptionResult(Uint8List data,
      {Uint8List? initializationVector,
      Uint8List? authenticationTag,
      Uint8List? additionalAuthenticatedData}) = EncryptionResultImpl;
}
