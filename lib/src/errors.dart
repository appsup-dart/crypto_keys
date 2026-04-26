class CryptoKeysException implements Exception {
  final String message;

  const CryptoKeysException(this.message);

  @override
  String toString() => 'CryptoKeysException: $message';
}

class AuthenticationTagMismatchException extends CryptoKeysException {
  const AuthenticationTagMismatchException(
      [super.message = 'Authentication tag verification failed.']);
}

class KeyUnwrapIntegrityException extends CryptoKeysException {
  const KeyUnwrapIntegrityException(
      [super.message = 'AES key unwrap integrity check failed.']);
}
