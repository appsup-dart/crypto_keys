// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'impl.dart';

// **************************************************************************
// BuiltValueGenerator
// **************************************************************************

// ignore_for_file: always_put_control_body_on_new_line
// ignore_for_file: annotate_overrides
// ignore_for_file: avoid_annotating_with_dynamic
// ignore_for_file: avoid_catches_without_on_clauses
// ignore_for_file: avoid_returning_this
// ignore_for_file: lines_longer_than_80_chars
// ignore_for_file: omit_local_variable_types
// ignore_for_file: prefer_expression_function_bodies
// ignore_for_file: sort_constructors_first

class _$RsaPublicKeyImpl extends RsaPublicKeyImpl {
  @override
  final BigInt exponent;
  @override
  final BigInt modulus;

  factory _$RsaPublicKeyImpl([void updates(RsaPublicKeyImplBuilder b)]) =>
      (new RsaPublicKeyImplBuilder()..update(updates)).build();

  _$RsaPublicKeyImpl._({this.exponent, this.modulus}) : super._() {
    if (exponent == null)
      throw new BuiltValueNullFieldError('RsaPublicKeyImpl', 'exponent');
    if (modulus == null)
      throw new BuiltValueNullFieldError('RsaPublicKeyImpl', 'modulus');
  }

  @override
  RsaPublicKeyImpl rebuild(void updates(RsaPublicKeyImplBuilder b)) =>
      (toBuilder()..update(updates)).build();

  @override
  RsaPublicKeyImplBuilder toBuilder() =>
      new RsaPublicKeyImplBuilder()..replace(this);

  @override
  bool operator ==(dynamic other) {
    if (identical(other, this)) return true;
    if (other is! RsaPublicKeyImpl) return false;
    return exponent == other.exponent && modulus == other.modulus;
  }

  @override
  int get hashCode {
    return $jf($jc($jc(0, exponent.hashCode), modulus.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('RsaPublicKeyImpl')
          ..add('exponent', exponent)
          ..add('modulus', modulus))
        .toString();
  }
}

class RsaPublicKeyImplBuilder
    implements Builder<RsaPublicKeyImpl, RsaPublicKeyImplBuilder> {
  _$RsaPublicKeyImpl _$v;

  BigInt _exponent;

  BigInt get exponent => _$this._exponent;

  set exponent(BigInt exponent) => _$this._exponent = exponent;

  BigInt _modulus;

  BigInt get modulus => _$this._modulus;

  set modulus(BigInt modulus) => _$this._modulus = modulus;

  RsaPublicKeyImplBuilder();

  RsaPublicKeyImplBuilder get _$this {
    if (_$v != null) {
      _exponent = _$v.exponent;
      _modulus = _$v.modulus;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(RsaPublicKeyImpl other) {
    if (other == null) throw new ArgumentError.notNull('other');
    _$v = other as _$RsaPublicKeyImpl;
  }

  @override
  void update(void updates(RsaPublicKeyImplBuilder b)) {
    if (updates != null) updates(this);
  }

  @override
  _$RsaPublicKeyImpl build() {
    final _$result =
        _$v ?? new _$RsaPublicKeyImpl._(exponent: exponent, modulus: modulus);
    replace(_$result);
    return _$result;
  }
}

class _$RsaPrivateKeyImpl extends RsaPrivateKeyImpl {
  @override
  final BigInt privateExponent;
  @override
  final BigInt firstPrimeFactor;
  @override
  final BigInt secondPrimeFactor;
  @override
  final BigInt modulus;

  factory _$RsaPrivateKeyImpl([void updates(RsaPrivateKeyImplBuilder b)]) =>
      (new RsaPrivateKeyImplBuilder()..update(updates)).build();

  _$RsaPrivateKeyImpl._(
      {this.privateExponent,
      this.firstPrimeFactor,
      this.secondPrimeFactor,
      this.modulus})
      : super._() {
    if (privateExponent == null)
      throw new BuiltValueNullFieldError(
          'RsaPrivateKeyImpl', 'privateExponent');
    if (firstPrimeFactor == null)
      throw new BuiltValueNullFieldError(
          'RsaPrivateKeyImpl', 'firstPrimeFactor');
    if (secondPrimeFactor == null)
      throw new BuiltValueNullFieldError(
          'RsaPrivateKeyImpl', 'secondPrimeFactor');
    if (modulus == null)
      throw new BuiltValueNullFieldError('RsaPrivateKeyImpl', 'modulus');
  }

  @override
  RsaPrivateKeyImpl rebuild(void updates(RsaPrivateKeyImplBuilder b)) =>
      (toBuilder()..update(updates)).build();

  @override
  RsaPrivateKeyImplBuilder toBuilder() =>
      new RsaPrivateKeyImplBuilder()..replace(this);

  @override
  bool operator ==(dynamic other) {
    if (identical(other, this)) return true;
    if (other is! RsaPrivateKeyImpl) return false;
    return privateExponent == other.privateExponent &&
        firstPrimeFactor == other.firstPrimeFactor &&
        secondPrimeFactor == other.secondPrimeFactor &&
        modulus == other.modulus;
  }

  @override
  int get hashCode {
    return $jf($jc(
        $jc($jc($jc(0, privateExponent.hashCode), firstPrimeFactor.hashCode),
            secondPrimeFactor.hashCode),
        modulus.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('RsaPrivateKeyImpl')
          ..add('privateExponent', privateExponent)
          ..add('firstPrimeFactor', firstPrimeFactor)
          ..add('secondPrimeFactor', secondPrimeFactor)
          ..add('modulus', modulus))
        .toString();
  }
}

class RsaPrivateKeyImplBuilder
    implements Builder<RsaPrivateKeyImpl, RsaPrivateKeyImplBuilder> {
  _$RsaPrivateKeyImpl _$v;

  BigInt _privateExponent;

  BigInt get privateExponent => _$this._privateExponent;

  set privateExponent(BigInt privateExponent) =>
      _$this._privateExponent = privateExponent;

  BigInt _firstPrimeFactor;

  BigInt get firstPrimeFactor => _$this._firstPrimeFactor;

  set firstPrimeFactor(BigInt firstPrimeFactor) =>
      _$this._firstPrimeFactor = firstPrimeFactor;

  BigInt _secondPrimeFactor;

  BigInt get secondPrimeFactor => _$this._secondPrimeFactor;

  set secondPrimeFactor(BigInt secondPrimeFactor) =>
      _$this._secondPrimeFactor = secondPrimeFactor;

  BigInt _modulus;

  BigInt get modulus => _$this._modulus;

  set modulus(BigInt modulus) => _$this._modulus = modulus;

  RsaPrivateKeyImplBuilder();

  RsaPrivateKeyImplBuilder get _$this {
    if (_$v != null) {
      _privateExponent = _$v.privateExponent;
      _firstPrimeFactor = _$v.firstPrimeFactor;
      _secondPrimeFactor = _$v.secondPrimeFactor;
      _modulus = _$v.modulus;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(RsaPrivateKeyImpl other) {
    if (other == null) throw new ArgumentError.notNull('other');
    _$v = other as _$RsaPrivateKeyImpl;
  }

  @override
  void update(void updates(RsaPrivateKeyImplBuilder b)) {
    if (updates != null) updates(this);
  }

  @override
  _$RsaPrivateKeyImpl build() {
    final _$result = _$v ??
        new _$RsaPrivateKeyImpl._(
            privateExponent: privateExponent,
            firstPrimeFactor: firstPrimeFactor,
            secondPrimeFactor: secondPrimeFactor,
            modulus: modulus);
    replace(_$result);
    return _$result;
  }
}

class _$EcPublicKeyImpl extends EcPublicKeyImpl {
  @override
  final BigInt xCoordinate;
  @override
  final BigInt yCoordinate;
  @override
  final Identifier curve;

  factory _$EcPublicKeyImpl([void updates(EcPublicKeyImplBuilder b)]) =>
      (new EcPublicKeyImplBuilder()..update(updates)).build();

  _$EcPublicKeyImpl._({this.xCoordinate, this.yCoordinate, this.curve})
      : super._() {
    if (xCoordinate == null)
      throw new BuiltValueNullFieldError('EcPublicKeyImpl', 'xCoordinate');
    if (yCoordinate == null)
      throw new BuiltValueNullFieldError('EcPublicKeyImpl', 'yCoordinate');
    if (curve == null)
      throw new BuiltValueNullFieldError('EcPublicKeyImpl', 'curve');
  }

  @override
  EcPublicKeyImpl rebuild(void updates(EcPublicKeyImplBuilder b)) =>
      (toBuilder()..update(updates)).build();

  @override
  EcPublicKeyImplBuilder toBuilder() =>
      new EcPublicKeyImplBuilder()..replace(this);

  @override
  bool operator ==(dynamic other) {
    if (identical(other, this)) return true;
    if (other is! EcPublicKeyImpl) return false;
    return xCoordinate == other.xCoordinate &&
        yCoordinate == other.yCoordinate &&
        curve == other.curve;
  }

  @override
  int get hashCode {
    return $jf($jc($jc($jc(0, xCoordinate.hashCode), yCoordinate.hashCode),
        curve.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('EcPublicKeyImpl')
          ..add('xCoordinate', xCoordinate)
          ..add('yCoordinate', yCoordinate)
          ..add('curve', curve))
        .toString();
  }
}

class EcPublicKeyImplBuilder
    implements Builder<EcPublicKeyImpl, EcPublicKeyImplBuilder> {
  _$EcPublicKeyImpl _$v;

  BigInt _xCoordinate;

  BigInt get xCoordinate => _$this._xCoordinate;

  set xCoordinate(BigInt xCoordinate) => _$this._xCoordinate = xCoordinate;

  BigInt _yCoordinate;

  BigInt get yCoordinate => _$this._yCoordinate;

  set yCoordinate(BigInt yCoordinate) => _$this._yCoordinate = yCoordinate;

  Identifier _curve;

  Identifier get curve => _$this._curve;

  set curve(Identifier curve) => _$this._curve = curve;

  EcPublicKeyImplBuilder();

  EcPublicKeyImplBuilder get _$this {
    if (_$v != null) {
      _xCoordinate = _$v.xCoordinate;
      _yCoordinate = _$v.yCoordinate;
      _curve = _$v.curve;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(EcPublicKeyImpl other) {
    if (other == null) throw new ArgumentError.notNull('other');
    _$v = other as _$EcPublicKeyImpl;
  }

  @override
  void update(void updates(EcPublicKeyImplBuilder b)) {
    if (updates != null) updates(this);
  }

  @override
  _$EcPublicKeyImpl build() {
    final _$result = _$v ??
        new _$EcPublicKeyImpl._(
            xCoordinate: xCoordinate, yCoordinate: yCoordinate, curve: curve);
    replace(_$result);
    return _$result;
  }
}

class _$EcPrivateKeyImpl extends EcPrivateKeyImpl {
  @override
  final BigInt eccPrivateKey;
  @override
  final Identifier curve;

  factory _$EcPrivateKeyImpl([void updates(EcPrivateKeyImplBuilder b)]) =>
      (new EcPrivateKeyImplBuilder()..update(updates)).build();

  _$EcPrivateKeyImpl._({this.eccPrivateKey, this.curve}) : super._() {
    if (eccPrivateKey == null)
      throw new BuiltValueNullFieldError('EcPrivateKeyImpl', 'eccPrivateKey');
    if (curve == null)
      throw new BuiltValueNullFieldError('EcPrivateKeyImpl', 'curve');
  }

  @override
  EcPrivateKeyImpl rebuild(void updates(EcPrivateKeyImplBuilder b)) =>
      (toBuilder()..update(updates)).build();

  @override
  EcPrivateKeyImplBuilder toBuilder() =>
      new EcPrivateKeyImplBuilder()..replace(this);

  @override
  bool operator ==(dynamic other) {
    if (identical(other, this)) return true;
    if (other is! EcPrivateKeyImpl) return false;
    return eccPrivateKey == other.eccPrivateKey && curve == other.curve;
  }

  @override
  int get hashCode {
    return $jf($jc($jc(0, eccPrivateKey.hashCode), curve.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('EcPrivateKeyImpl')
          ..add('eccPrivateKey', eccPrivateKey)
          ..add('curve', curve))
        .toString();
  }
}

class EcPrivateKeyImplBuilder
    implements Builder<EcPrivateKeyImpl, EcPrivateKeyImplBuilder> {
  _$EcPrivateKeyImpl _$v;

  BigInt _eccPrivateKey;

  BigInt get eccPrivateKey => _$this._eccPrivateKey;

  set eccPrivateKey(BigInt eccPrivateKey) =>
      _$this._eccPrivateKey = eccPrivateKey;

  Identifier _curve;

  Identifier get curve => _$this._curve;

  set curve(Identifier curve) => _$this._curve = curve;

  EcPrivateKeyImplBuilder();

  EcPrivateKeyImplBuilder get _$this {
    if (_$v != null) {
      _eccPrivateKey = _$v.eccPrivateKey;
      _curve = _$v.curve;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(EcPrivateKeyImpl other) {
    if (other == null) throw new ArgumentError.notNull('other');
    _$v = other as _$EcPrivateKeyImpl;
  }

  @override
  void update(void updates(EcPrivateKeyImplBuilder b)) {
    if (updates != null) updates(this);
  }

  @override
  _$EcPrivateKeyImpl build() {
    final _$result = _$v ??
        new _$EcPrivateKeyImpl._(eccPrivateKey: eccPrivateKey, curve: curve);
    replace(_$result);
    return _$result;
  }
}

class _$SymmetricKeyImpl extends SymmetricKeyImpl {
  @override
  final Uint8List keyValue;

  factory _$SymmetricKeyImpl([void updates(SymmetricKeyImplBuilder b)]) =>
      (new SymmetricKeyImplBuilder()..update(updates)).build();

  _$SymmetricKeyImpl._({this.keyValue}) : super._() {
    if (keyValue == null)
      throw new BuiltValueNullFieldError('SymmetricKeyImpl', 'keyValue');
  }

  @override
  SymmetricKeyImpl rebuild(void updates(SymmetricKeyImplBuilder b)) =>
      (toBuilder()..update(updates)).build();

  @override
  SymmetricKeyImplBuilder toBuilder() =>
      new SymmetricKeyImplBuilder()..replace(this);

  @override
  bool operator ==(dynamic other) {
    if (identical(other, this)) return true;
    if (other is! SymmetricKeyImpl) return false;
    return keyValue == other.keyValue;
  }

  @override
  int get hashCode {
    return $jf($jc(0, keyValue.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('SymmetricKeyImpl')
          ..add('keyValue', keyValue))
        .toString();
  }
}

class SymmetricKeyImplBuilder
    implements Builder<SymmetricKeyImpl, SymmetricKeyImplBuilder> {
  _$SymmetricKeyImpl _$v;

  Uint8List _keyValue;

  Uint8List get keyValue => _$this._keyValue;

  set keyValue(Uint8List keyValue) => _$this._keyValue = keyValue;

  SymmetricKeyImplBuilder();

  SymmetricKeyImplBuilder get _$this {
    if (_$v != null) {
      _keyValue = _$v.keyValue;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(SymmetricKeyImpl other) {
    if (other == null) throw new ArgumentError.notNull('other');
    _$v = other as _$SymmetricKeyImpl;
  }

  @override
  void update(void updates(SymmetricKeyImplBuilder b)) {
    if (updates != null) updates(this);
  }

  @override
  _$SymmetricKeyImpl build() {
    final _$result = _$v ?? new _$SymmetricKeyImpl._(keyValue: keyValue);
    replace(_$result);
    return _$result;
  }
}

class _$SignatureImpl extends SignatureImpl {
  @override
  final BuiltList<int> built_data;
  Uint8List __data;

  factory _$SignatureImpl([void updates(SignatureImplBuilder b)]) =>
      (new SignatureImplBuilder()..update(updates)).build();

  _$SignatureImpl._({this.built_data}) : super._() {
    if (built_data == null)
      throw new BuiltValueNullFieldError('SignatureImpl', 'built_data');
  }

  @override
  Uint8List get data => __data ??= super.data;

  @override
  SignatureImpl rebuild(void updates(SignatureImplBuilder b)) =>
      (toBuilder()..update(updates)).build();

  @override
  SignatureImplBuilder toBuilder() => new SignatureImplBuilder()..replace(this);

  @override
  bool operator ==(dynamic other) {
    if (identical(other, this)) return true;
    if (other is! SignatureImpl) return false;
    return built_data == other.built_data;
  }

  @override
  int get hashCode {
    return $jf($jc(0, built_data.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('SignatureImpl')
          ..add('built_data', built_data))
        .toString();
  }
}

class SignatureImplBuilder
    implements Builder<SignatureImpl, SignatureImplBuilder> {
  _$SignatureImpl _$v;

  ListBuilder<int> _built_data;

  ListBuilder<int> get built_data =>
      _$this._built_data ??= new ListBuilder<int>();

  set built_data(ListBuilder<int> built_data) =>
      _$this._built_data = built_data;

  SignatureImplBuilder();

  SignatureImplBuilder get _$this {
    if (_$v != null) {
      _built_data = _$v.built_data?.toBuilder();
      _$v = null;
    }
    return this;
  }

  @override
  void replace(SignatureImpl other) {
    if (other == null) throw new ArgumentError.notNull('other');
    _$v = other as _$SignatureImpl;
  }

  @override
  void update(void updates(SignatureImplBuilder b)) {
    if (updates != null) updates(this);
  }

  @override
  _$SignatureImpl build() {
    _$SignatureImpl _$result;
    try {
      _$result = _$v ?? new _$SignatureImpl._(built_data: built_data.build());
    } catch (_) {
      String _$failedField;
      try {
        _$failedField = 'built_data';
        built_data.build();
      } catch (e) {
        throw new BuiltValueNestedFieldError(
            'SignatureImpl', _$failedField, e.toString());
      }
      rethrow;
    }
    replace(_$result);
    return _$result;
  }
}

class _$EncryptionResultImpl extends EncryptionResultImpl {
  @override
  final BuiltList<int> built_data;
  @override
  final BuiltList<int> built_initializationVector;
  @override
  final BuiltList<int> built_authenticationTag;
  @override
  final BuiltList<int> built_additionalAuthenticatedData;
  Uint8List __data;
  Uint8List __initializationVector;
  Uint8List __authenticationTag;
  Uint8List __additionalAuthenticatedData;

  factory _$EncryptionResultImpl(
          [void updates(EncryptionResultImplBuilder b)]) =>
      (new EncryptionResultImplBuilder()..update(updates)).build();

  _$EncryptionResultImpl._(
      {this.built_data,
      this.built_initializationVector,
      this.built_authenticationTag,
      this.built_additionalAuthenticatedData})
      : super._() {
    if (built_data == null)
      throw new BuiltValueNullFieldError('EncryptionResultImpl', 'built_data');
  }

  @override
  Uint8List get data => __data ??= super.data;

  @override
  Uint8List get initializationVector =>
      __initializationVector ??= super.initializationVector;

  @override
  Uint8List get authenticationTag =>
      __authenticationTag ??= super.authenticationTag;

  @override
  Uint8List get additionalAuthenticatedData =>
      __additionalAuthenticatedData ??= super.additionalAuthenticatedData;

  @override
  EncryptionResultImpl rebuild(void updates(EncryptionResultImplBuilder b)) =>
      (toBuilder()..update(updates)).build();

  @override
  EncryptionResultImplBuilder toBuilder() =>
      new EncryptionResultImplBuilder()..replace(this);

  @override
  bool operator ==(dynamic other) {
    if (identical(other, this)) return true;
    if (other is! EncryptionResultImpl) return false;
    return built_data == other.built_data &&
        built_initializationVector == other.built_initializationVector &&
        built_authenticationTag == other.built_authenticationTag &&
        built_additionalAuthenticatedData ==
            other.built_additionalAuthenticatedData;
  }

  @override
  int get hashCode {
    return $jf($jc(
        $jc(
            $jc($jc(0, built_data.hashCode),
                built_initializationVector.hashCode),
            built_authenticationTag.hashCode),
        built_additionalAuthenticatedData.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('EncryptionResultImpl')
          ..add('built_data', built_data)
          ..add('built_initializationVector', built_initializationVector)
          ..add('built_authenticationTag', built_authenticationTag)
          ..add('built_additionalAuthenticatedData',
              built_additionalAuthenticatedData))
        .toString();
  }
}

class EncryptionResultImplBuilder
    implements Builder<EncryptionResultImpl, EncryptionResultImplBuilder> {
  _$EncryptionResultImpl _$v;

  ListBuilder<int> _built_data;

  ListBuilder<int> get built_data =>
      _$this._built_data ??= new ListBuilder<int>();

  set built_data(ListBuilder<int> built_data) =>
      _$this._built_data = built_data;

  ListBuilder<int> _built_initializationVector;

  ListBuilder<int> get built_initializationVector =>
      _$this._built_initializationVector ??= new ListBuilder<int>();

  set built_initializationVector(ListBuilder<int> built_initializationVector) =>
      _$this._built_initializationVector = built_initializationVector;

  ListBuilder<int> _built_authenticationTag;

  ListBuilder<int> get built_authenticationTag =>
      _$this._built_authenticationTag ??= new ListBuilder<int>();

  set built_authenticationTag(ListBuilder<int> built_authenticationTag) =>
      _$this._built_authenticationTag = built_authenticationTag;

  ListBuilder<int> _built_additionalAuthenticatedData;

  ListBuilder<int> get built_additionalAuthenticatedData =>
      _$this._built_additionalAuthenticatedData ??= new ListBuilder<int>();

  set built_additionalAuthenticatedData(
          ListBuilder<int> built_additionalAuthenticatedData) =>
      _$this._built_additionalAuthenticatedData =
          built_additionalAuthenticatedData;

  EncryptionResultImplBuilder();

  EncryptionResultImplBuilder get _$this {
    if (_$v != null) {
      _built_data = _$v.built_data?.toBuilder();
      _built_initializationVector = _$v.built_initializationVector?.toBuilder();
      _built_authenticationTag = _$v.built_authenticationTag?.toBuilder();
      _built_additionalAuthenticatedData =
          _$v.built_additionalAuthenticatedData?.toBuilder();
      _$v = null;
    }
    return this;
  }

  @override
  void replace(EncryptionResultImpl other) {
    if (other == null) throw new ArgumentError.notNull('other');
    _$v = other as _$EncryptionResultImpl;
  }

  @override
  void update(void updates(EncryptionResultImplBuilder b)) {
    if (updates != null) updates(this);
  }

  @override
  _$EncryptionResultImpl build() {
    _$EncryptionResultImpl _$result;
    try {
      _$result = _$v ??
          new _$EncryptionResultImpl._(
              built_data: built_data.build(),
              built_initializationVector: _built_initializationVector?.build(),
              built_authenticationTag: _built_authenticationTag?.build(),
              built_additionalAuthenticatedData:
                  _built_additionalAuthenticatedData?.build());
    } catch (_) {
      String _$failedField;
      try {
        _$failedField = 'built_data';
        built_data.build();
        _$failedField = 'built_initializationVector';
        _built_initializationVector?.build();
        _$failedField = 'built_authenticationTag';
        _built_authenticationTag?.build();
        _$failedField = 'built_additionalAuthenticatedData';
        _built_additionalAuthenticatedData?.build();
      } catch (e) {
        throw new BuiltValueNestedFieldError(
            'EncryptionResultImpl', _$failedField, e.toString());
      }
      rethrow;
    }
    replace(_$result);
    return _$result;
  }
}
