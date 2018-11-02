import '../crypto_keys.dart';
import 'package:built_value/built_value.dart';
import 'package:built_collection/built_collection.dart';

import 'dart:typed_data';
import 'algorithms.dart';

part 'impl.g.dart';

abstract class RsaPublicKeyImpl extends PublicKey
    with Key
    implements
        RsaPublicKey,
        RsaKey,
        Built<RsaPublicKeyImpl, RsaPublicKeyImplBuilder> {
  RsaPublicKeyImpl._();

  factory RsaPublicKeyImpl({BigInt modulus, BigInt exponent}) =
      _$RsaPublicKeyImpl._;
}

abstract class RsaPrivateKeyImpl extends PrivateKey
    with Key
    implements
        RsaPrivateKey,
        RsaKey,
        Built<RsaPrivateKeyImpl, RsaPrivateKeyImplBuilder> {
  RsaPrivateKeyImpl._();

  factory RsaPrivateKeyImpl(
      {BigInt privateExponent,
      BigInt firstPrimeFactor,
      BigInt secondPrimeFactor,
      BigInt modulus}) = _$RsaPrivateKeyImpl._;
}

abstract class EcPublicKeyImpl extends PublicKey
    with Key
    implements
        EcPublicKey,
        EcKey,
        Built<EcPublicKeyImpl, EcPublicKeyImplBuilder> {
  EcPublicKeyImpl._();

  factory EcPublicKeyImpl(
      {BigInt xCoordinate,
      BigInt yCoordinate,
      Identifier curve}) = _$EcPublicKeyImpl._;
}

abstract class EcPrivateKeyImpl extends PrivateKey
    with Key
    implements
        EcPrivateKey,
        EcKey,
        Built<EcPrivateKeyImpl, EcPrivateKeyImplBuilder> {
  EcPrivateKeyImpl._();

  factory EcPrivateKeyImpl({BigInt eccPrivateKey, Identifier curve}) =
      _$EcPrivateKeyImpl._;
}

abstract class SymmetricKeyImpl extends Object
    with Key, PublicKey, PrivateKey
    implements SymmetricKey, Built<SymmetricKeyImpl, SymmetricKeyImplBuilder> {
  SymmetricKeyImpl._();

  factory SymmetricKeyImpl({Uint8List keyValue}) = _$SymmetricKeyImpl._;
}

abstract class SignatureImpl
    implements Signature, Built<SignatureImpl, SignatureImplBuilder> {
  BuiltList<int> get built_data;

  @override
  @memoized
  Uint8List get data => new Uint8List.fromList(built_data.asList());

  SignatureImpl._();

  factory SignatureImpl(Uint8List data) =>
      _$SignatureImpl._(built_data: new BuiltList(data));
}

abstract class EncryptionResultImpl
    implements
        EncryptionResult,
        Built<EncryptionResultImpl, EncryptionResultImplBuilder> {
  BuiltList<int> get built_data;

  @override
  @memoized
  Uint8List get data => new Uint8List.fromList(built_data.asList());

  @nullable
  BuiltList<int> get built_initializationVector;

  @override
  @memoized
  Uint8List get initializationVector => built_initializationVector == null
      ? null
      : new Uint8List.fromList(built_initializationVector.asList());

  @nullable
  BuiltList<int> get built_authenticationTag;

  @override
  @memoized
  Uint8List get authenticationTag => built_authenticationTag == null
      ? null
      : new Uint8List.fromList(built_authenticationTag.asList());

  @nullable
  BuiltList<int> get built_additionalAuthenticatedData;

  @override
  @memoized
  Uint8List get additionalAuthenticatedData =>
      built_additionalAuthenticatedData == null
          ? null
          : new Uint8List.fromList(built_additionalAuthenticatedData.asList());

  EncryptionResultImpl._();

  factory EncryptionResultImpl(Uint8List data,
          {Uint8List initializationVector,
          Uint8List authenticationTag,
          Uint8List additionalAuthenticatedData}) =>
      _$EncryptionResultImpl._(
          built_data: new BuiltList(data),
          built_initializationVector: initializationVector == null
              ? null
              : new BuiltList(initializationVector),
          built_additionalAuthenticatedData: additionalAuthenticatedData == null
              ? null
              : new BuiltList(additionalAuthenticatedData),
          built_authenticationTag: authenticationTag == null
              ? null
              : new BuiltList(authenticationTag));
}
