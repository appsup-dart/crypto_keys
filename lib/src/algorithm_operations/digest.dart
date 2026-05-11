import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:crypto_keys/src/utils/digest.dart';

extension DigestAlgorithmHashBytes on DigestAlgorithm {
  /// Computes the digest of [input] using this algorithm.
  Uint8List hashBytes(List<int> input) {
    final digest = algorithmImplementation;
    final bytes = Uint8List.fromList(input);
    digest.update(bytes, 0, bytes.length);
    final out = Uint8List(digest.digestSize);
    digest.doFinal(out, 0);
    return out;
  }
}
