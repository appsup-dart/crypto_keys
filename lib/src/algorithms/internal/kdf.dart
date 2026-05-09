part of '../../algorithms.dart';

final class ConcatKdfAlgorithm extends SecretKdfAlgorithm {
  final DigestAlgorithm hash;

  const ConcatKdfAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ConcatKdfAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(1, hash);
}

final class Pbkdf2KdfAlgorithm extends PasswordKdfAlgorithm {
  final DigestAlgorithm hash;

  const Pbkdf2KdfAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Pbkdf2KdfAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(2, hash);
}

final class HkdfKdfAlgorithm extends SecretKdfAlgorithm {
  final DigestAlgorithm hash;

  const HkdfKdfAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is HkdfKdfAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(3, hash);
}

final class Argon2idKdfAlgorithm extends PasswordKdfAlgorithm {
  const Argon2idKdfAlgorithm() : super();

  @override
  bool operator ==(Object other) => other is Argon2idKdfAlgorithm;

  @override
  int get hashCode => (Argon2idKdfAlgorithm).hashCode;
}
