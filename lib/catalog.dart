/// Browsable **algorithm catalog**: [algorithms] groups `signing`, `encryption`,
/// `keyAgreement`, `kdf`, and `digest` for IDE exploration.
///
/// Focus: **algorithm-first** calls—extensions exported here put an [algorithms] leaf **first**, then material / keys (`sign`, `verify`, `deriveBits`, `encrypt`, …).
///
/// ```dart
/// algorithms.signing.hmac.sha256.sign(privateKey, message);
/// algorithms.kdf.password.pbkdf2.sha256.deriveBits(
///     password,
///     salt: salt,
///     iterations: 100_000,
///     keyBitLength: 256);
/// ```
library;

import 'src/catalog.dart';
export 'src/catalog.dart';
export 'src/algorithm_operations.dart';
