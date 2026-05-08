/// Browsable catalog for algorithm discovery.
///
/// Import this library when you want a structured, discoverable path to
/// identifiers, for example:
/// `algorithms.signing.hmac.sha256` or `algorithms.encryption.aes.gcm`.
///
/// Example:
/// ```dart
/// import 'package:crypto_keys/catalog.dart';
///
/// final sigAlg = algorithms.signing.rsa.pkcs1.sha256;
/// final encAlg = algorithms.encryption.aes.gcm;
/// final kdfAlg = algorithms.derivation.hkdf.withHash(.sha256);
/// ```
///
/// This entrypoint is focused on ergonomics and documentation discoverability.
/// Core cryptographic types and operations remain in `package:crypto_keys/crypto_keys.dart`.
library;

export 'src/catalog.dart';
