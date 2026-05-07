import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'pointycastle_ext.dart' as pce;

part 'algorithms/common.dart';
part 'algorithms/derivation.dart';
part 'algorithms/digest.dart';
part 'algorithms/encryption.dart';
part 'algorithms/signing.dart';

/// Contains the identifiers for supported algorithms
///
/// ## Encryption algorithms
///
/// ### AES
///
/// - [algorithms.encryption.aes.cbc] AES CBC
/// - [algorithms.encryption.aes.cbcWithHmac] AES CBC with HMAC
/// - [algorithms.encryption.aes.gcm] AES GCM
final algorithms = Algorithms();
