part of '../crypto_keys.dart';

/// Base class for Octet Key Pairs (OKP-Keys)
abstract class OkpKey extends Key {
  /// The cryptographic curve used with the key
  Identifier get curve;
}

/// An OKP public key
abstract class OkpPublicKey extends OkpKey implements PublicKey {
  /// The public key value
  Uint8List get okpPublicKey;

  factory OkpPublicKey(
      {required Uint8List okpPublicKey,
      required Identifier curve}) = OkpPublicKeyImpl;
}

/// An OKP private key
abstract class OkpPrivateKey extends OkpKey implements PrivateKey {
  /// The OKP private key value
  Uint8List get okpPrivateKey;

  factory OkpPrivateKey(
      {required Uint8List okpPrivateKey,
      required Identifier curve}) = OkpPrivateKeyImpl;
}
