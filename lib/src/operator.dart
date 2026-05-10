part of '../crypto_keys.dart';

/// Base class for cryptographic operations
abstract class Operator<T extends KeyMaterial> {
  /// The key material used for this operation
  final T keyMaterial;

  /// The algorithm used for this operation
  final Algorithm algorithm;

  Operator._(this.algorithm, this.keyMaterial);
  Operator(this.algorithm, this.keyMaterial);
}

/// Operator for signing
abstract class Signer<T extends PrivateKey> extends Operator<T> {
  Signer(SigningAlgorithm super.algorithm, super.key) : super._();

  /// Signs the input [data] using the [keyMaterial] and [algorithm]
  Signature sign(List<int> data);
}

/// Operator for verifying a signature
abstract class Verifier<T extends PublicKey> extends Operator<T> {
  Verifier(SigningAlgorithm super.algorithm, super.key) : super._();

  /// Verifies that [signature] is a valid signature for the input [data] using
  /// the [keyMaterial] and [algorithm]
  bool verify(Uint8List data, Signature signature);
}

/// Represents the result of signing some data
class Signature {
  /// Byte representation of the signature
  final Uint8List data;

  Signature(Uint8List data) : data = Uint8List.fromList(data);

  @override
  int get hashCode => const ListEquality().hash(data);

  @override
  bool operator ==(other) =>
      other is Signature && const ListEquality().equals(other.data, data);
}

/// Stateful encryptor binding a concrete [EncryptionAlgorithm] to key material.
///
/// Obtained via `EncryptingPublicKey.createEncrypter` implementations
/// (`SymmetricKey`, `RsaPublicKey`, …).
abstract class Encrypter<T extends PublicKey> extends Operator<T> {
  Encrypter(EncryptionAlgorithm super.algorithm, super.key) : super._();

  /// Encrypts `input`, returning ciphertext plus IV/tag/AAD metadata captured in
  /// [EncryptionResult].
  ///
  /// When an IV/nonce is required yet omitted, this package generates unpredictable
  /// random bytes automatically—persist them alongside the ciphertext for decryption.
  EncryptionResult encrypt(
    Uint8List input, {
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  });
}

/// Inverse of [Encrypter], restoring plaintext from [EncryptionResult].
abstract class Decrypter<T extends PrivateKey> extends Operator<T> {
  Decrypter(EncryptionAlgorithm super.algorithm, super.key) : super._();

  /// Decrypts a prior [EncryptionResult] using the same symmetric key or RSA private
  /// key that produced it.
  Uint8List decrypt(EncryptionResult input);
}

/// Serialized encryption payload (ciphertext + IV/nonce + authentication tag + optional
/// AAD echo) returned from [Encrypter.encrypt].
///
/// Store or transmit the non-secret fields together so [Decrypter.decrypt] can
/// reconstruct the original plaintext.
class EncryptionResult {
  /// Byte representation of the ciphertext
  final Uint8List data;

  /// The initialization vector used for encrypting when required by the
  /// algorithm
  final Uint8List? initializationVector;

  final Uint8List? authenticationTag;

  final Uint8List? additionalAuthenticatedData;

  EncryptionResult(
    Uint8List data, {
    Uint8List? initializationVector,
    Uint8List? authenticationTag,
    Uint8List? additionalAuthenticatedData,
  }) : data = Uint8List.fromList(data),
       initializationVector = initializationVector == null
           ? null
           : Uint8List.fromList(initializationVector),
       authenticationTag = authenticationTag == null
           ? null
           : Uint8List.fromList(authenticationTag),
       additionalAuthenticatedData = additionalAuthenticatedData == null
           ? null
           : Uint8List.fromList(additionalAuthenticatedData);

  @override
  int get hashCode => Object.hash(
    const ListEquality().hash(data),
    const ListEquality().hash(initializationVector),
    const ListEquality().hash(authenticationTag),
    const ListEquality().hash(additionalAuthenticatedData),
  );

  @override
  bool operator ==(other) =>
      other is EncryptionResult &&
      const ListEquality().equals(other.data, data) &&
      const ListEquality().equals(
        other.initializationVector,
        initializationVector,
      ) &&
      const ListEquality().equals(other.authenticationTag, authenticationTag) &&
      const ListEquality().equals(
        other.additionalAuthenticatedData,
        additionalAuthenticatedData,
      );
}
