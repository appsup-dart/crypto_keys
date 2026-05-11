import 'package:crypto_keys/catalog.dart';
import 'package:crypto_keys/src/algorithms.dart';
import 'package:test/test.dart';

/// Decodes a contiguous lowercase hex string into bytes (for known test vectors).
List<int> _hex(String s) {
  assert(s.length.isEven, 'hex string length must be even');
  final out = <int>[];
  for (var i = 0; i < s.length; i += 2) {
    out.add(int.parse(s.substring(i, i + 2), radix: 16));
  }
  return out;
}

void main() {
  test('every SigningAlgorithm resolves sign / verify extensions', () {
    void verify(SigningAlgorithm algorithm) {
      switch (algorithm) {
        case SymmetricSigningAlgorithm():
          algorithm.sign;
          algorithm.verify;
        case RsaSigningAlgorithm():
          algorithm.sign;
          algorithm.verify;
        case EcSigningAlgorithm():
          algorithm.sign;
          algorithm.verify;
        case Ed25519SigningAlgorithm():
          algorithm.sign;
          algorithm.verify;
      }
    }

    verify;
  });

  test('every EncryptionAlgorithm resolves encrypt / decrypt extensions', () {
    void verify(EncryptionAlgorithm algorithm) {
      switch (algorithm) {
        case SymmetricEncryptionAlgorithm():
          algorithm.encrypt;
          algorithm.decrypt;
        case RsaEncryptionAlgorithm():
          algorithm.encrypt;
          algorithm.decrypt;
      }
    }

    verify;
  });

  test('every KeyAgreementAlgorithm has a deriveSharedSecret extension', () {
    void verify(KeyAgreementAlgorithm algorithm) {
      switch (algorithm) {
        case EcdhKeyAgreementAlgorithm():
          algorithm.deriveSharedSecret;
        case X25519KeyAgreementAlgorithm():
          algorithm.deriveSharedSecret;
      }
    }

    verify;
  });

  test('every KdfAlgorithm has a deriveBits extension method', () {
    // Analysis-time guard: exhaustive switch on [KdfAlgorithm] and `.deriveBits`
    // resolving on each concrete type (needs an extension); `dart analyze`
    // fails when a variant is missing or lacks the method.
    void verify(KdfAlgorithm algorithm) {
      switch (algorithm) {
        case Pbkdf2Algorithm():
          algorithm.deriveBits;
        case Argon2idKdfAlgorithm():
          algorithm.deriveBits;
        case ConcatKdfAlgorithm():
          algorithm.deriveBits;
        case HkdfAlgorithm():
          algorithm.deriveBits;
      }
    }

    verify;
  });

  test('every DigestAlgorithm has a hashBytes extension method', () {
    void verify(DigestAlgorithm algorithm) {
      switch (algorithm) {
        case DigestSha1():
          algorithm.hashBytes;
        case DigestSha2():
          algorithm.hashBytes;
        case DigestSha3():
          algorithm.hashBytes;
      }
    }

    verify;
  });

  group('DigestAlgorithm.hashBytes known vectors', () {
    final abc = 'abc'.codeUnits;

    test('SHA-1 "abc" (FIPS 180-1 / RFC 3174)', () {
      expect(
        algorithms.digest.sha1.hashBytes(abc),
        _hex('a9993e364706816aba3e25717850c26c9cd0d89d'),
      );
    });

    test('SHA-224 "abc" (FIPS 180-4)', () {
      expect(
        algorithms.digest.sha224.hashBytes(abc),
        _hex('23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'),
      );
    });

    test('SHA-256 empty message (FIPS 180-4)', () {
      expect(
        algorithms.digest.sha256.hashBytes([]),
        _hex(
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ),
      );
    });

    test('SHA-256 "abc" (FIPS 180-4)', () {
      expect(
        algorithms.digest.sha256.hashBytes(abc),
        _hex(
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        ),
      );
    });

    test('SHA-384 "abc" (FIPS 180-4)', () {
      expect(
        algorithms.digest.sha384.hashBytes(abc),
        _hex(
          'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed'
          '8086072ba1e7cc2358baeca134c825a7',
        ),
      );
    });

    test('SHA-512 "abc" (FIPS 180-4)', () {
      expect(
        algorithms.digest.sha512.hashBytes(abc),
        _hex(
          'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
          '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
        ),
      );
    });

    test('SHA-512/224 "abc" (FIPS 180-4)', () {
      expect(
        algorithms.digest.sha512t(28).hashBytes(abc),
        _hex(
          '4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa',
        ),
      );
    });

    test('SHA-512/256 "abc" (FIPS 180-4)', () {
      expect(
        algorithms.digest.sha512t(32).hashBytes(abc),
        _hex(
          '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23',
        ),
      );
    });

    test('SHA3-224 "abc" (FIPS 202)', () {
      expect(
        algorithms.digest.sha3_224.hashBytes(abc),
        _hex(
          'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
        ),
      );
    });

    test('SHA3-256 empty message (FIPS 202)', () {
      expect(
        algorithms.digest.sha3_256.hashBytes([]),
        _hex(
          'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
        ),
      );
    });

    test('SHA3-256 "abc" (FIPS 202)', () {
      expect(
        algorithms.digest.sha3_256.hashBytes(abc),
        _hex(
          '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
        ),
      );
    });

    test('SHA3-384 "abc" (FIPS 202)', () {
      expect(
        algorithms.digest.sha3_384.hashBytes(abc),
        _hex(
          'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2'
          '98d88cea927ac7f539f1edf228376d25',
        ),
      );
    });

    test('SHA3-512 "abc" (FIPS 202)', () {
      expect(
        algorithms.digest.sha3_512.hashBytes(abc),
        _hex(
          'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e'
          '10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
        ),
      );
    });
  });
}
