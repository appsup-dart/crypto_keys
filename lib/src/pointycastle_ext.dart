import 'package:pointycastle/export.dart';
import 'dart:typed_data';
import 'dart:math' show min;

class ParametersWithIVAndAad<UnderlyingParameters extends CipherParameters>
    extends ParametersWithIV<UnderlyingParameters> {
  final Uint8List aad;

  ParametersWithIVAndAad(
      UnderlyingParameters parameters, Uint8List iv, this.aad)
      : super(parameters, iv);
}

/// Implementation of Galois/Counter Mode (GCM) mode on top of a [BlockCipher].
class GCMBlockCipher extends BlockCipherWithAuthenticationTag {
  final BlockCipher _underlyingCipher;

  Uint8List _counter;

  BigInt _e;

  BigInt _h;
  BigInt _x;
  BigInt _e0;

  int _processedBytes;

  GCMBlockCipher(this._underlyingCipher);

  String get algorithmName => "${_underlyingCipher.algorithmName}/GCM";

  int get blockSize => _underlyingCipher.blockSize;

  Uint8List _computeInitialCounter(Uint8List iv) {
    Uint8List counter = new Uint8List(16);

    if (iv.length == 12) {
      counter.setAll(0, iv);
      counter.fillRange(12, 16, 0);
      counter[15] = 1;
    } else {
      var x = BigInt.zero;
      var block = new Uint8List(16);
      for (var i = 0; i < iv.length; i += 16) {
        block.setAll(0, iv.sublist(i, min(i + 16, iv.length)));
        block.fillRange(min(i + 16, iv.length) - i, 16, 0);
        var a = _toBigInt(block);
        x = _mult(x ^ a, _h);
      }
      x = _mult(x ^ new BigInt.from(iv.length * 8), _h);

      counter.fillRange(0, 16, 0);
      var i = counter.length - 1;
      while (x.bitLength > 0) {
        counter[i--] = (x % b256).toInt();
        x >>= 8;
      }
    }

    return counter;
  }

  static final _computeBuffer = new Uint8List(16);

  BigInt _computeE(Uint8List inp) {
    _underlyingCipher.processBlock(inp, 0, _computeBuffer, 0);
    return _toBigInt(_computeBuffer);
  }

  void reset() {
    _processedBytes = 0;

    _h = _computeE(new Uint8List(16));
    _counter = _computeInitialCounter(_iv);
    _e0 = _computeE(_counter);
    _x = BigInt.zero;

    _processAad();
  }

  void _processAad() {
    var block = new Uint8List(16);
    for (var i = 0; i < _aad.length; i += 16) {
      block.setAll(0, _aad.sublist(i, min(i + 16, _aad.length)));
      block.fillRange(min(i + 16, _aad.length) - i, 16, 0);
      var a = _toBigInt(block);
      _x = _mult(_x ^ a, _h);
    }
  }

  void initParameters(CipherParameters params) {
    _underlyingCipher.reset();
    _underlyingCipher.init(true, params);

    reset();
  }

  final BigInt r = BigInt.parse("11100001", radix: 2) << 120;
  final BigInt b256 = BigInt.from(256);
  final BigInt b255 = BigInt.parse("0xff");

  BigInt _toBigInt(Iterable<int> bytes) {
    return bytes.fold(BigInt.zero, (a, b) => (a << 8) + new BigInt.from(b));
  }

  Uint8List _toBytes(BigInt v, int length) {
    var out = new Uint8List(length);
    _writeBigInt(v, out);
    return out;
  }

  void _writeBigInt(BigInt v, Uint8List out) {
    for (var i = out.length - 1; i >= 0; i--) {
      out[i] = (v & b255).toInt();
      v >>= 8;
    }
  }

  BigInt _mult(BigInt x, BigInt y) {
    var v = x;
    var z = BigInt.zero;

    for (var i = 0; i < 128; i++) {
      if ((y >> (127 - i)) & BigInt.one == BigInt.one) {
        z ^= v;
      }
      if (v & BigInt.one == BigInt.zero) {
        v = v >> 1;
      } else {
        v = (v >> 1) ^ r;
      }
    }
    return z;
  }

  void _incCounter() {
    _counter[15]++;
    for (var i = 15; i >= 12 && _counter[i] == 256; i--) {
      _counter[i] = 0;
      if (i > 12) _counter[i - 1]++;
    }

    _e = _computeE(_counter);
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    var length =
        blockSize < inp.length - inpOff ? blockSize : inp.length - inpOff;
    _processedBytes += length;

    _incCounter();

    var padLength = (blockSize - length) * 8;

    var i = _toBigInt(inp.skip(inpOff).take(length));

    var o = i ^ (_e >> padLength);

    _writeBigInt(
        o, new Uint8List.view(out.buffer, out.offsetInBytes + outOff, length));

    var c = _encrypting ? o : i;
    c <<= padLength;
    _x = _mult(_x ^ c, _h);

    return length;
  }

  @override
  Uint8List finalizeTag() {
    var len = (new BigInt.from(aad.length) << (64 + 3)) +
        (new BigInt.from(_processedBytes) << 3);
    _x = _mult(_x ^ len, _h);

    var t = _x ^ _e0;

    return _toBytes(t, tagLength);
  }

  @override
  int get tagLength => 16;
}

String toHex(Iterable<int> bytes) {
  return bytes.map((b) => (b + 256).toRadixString(16).substring(1)).join();
}

abstract class BlockCipherWithAuthenticationTag implements BlockCipher {
  bool _encrypting;
  Uint8List _aad;
  Uint8List _iv;

  bool get isEncrypting => _encrypting;

  Uint8List get aad => _aad;

  Uint8List get iv => _iv;

  int get tagLength;

  @override
  Uint8List process(Uint8List data) {
    if (isEncrypting) {
      var ciphertext = processBlocks(data);
      var tag = finalizeTag();
      var out = new Uint8List(ciphertext.length + tag.length);
      out.setAll(0, ciphertext);
      out.setAll(ciphertext.length, tag);
      return out;
    } else {
      var ciphertext = new Uint8List.view(
          data.buffer, data.offsetInBytes, data.length - tagLength);
      var inTag = new Uint8List.view(
          data.buffer, data.offsetInBytes + ciphertext.length);
      var plaintext = processBlocks(ciphertext);

      var tag = finalizeTag();

      if (!_compareList(inTag, tag)) {
        throw "Auth error"; // TODO
      }
      return plaintext;
    }
  }

  Uint8List processBlocks(Uint8List data) {
    var inputBlocks = (data.length + blockSize - 1) ~/ blockSize;

    var out = new Uint8List(data.length);

    for (var i = 0; i < inputBlocks; i++) {
      var offset = (i * blockSize);
      processBlock(data, offset, out, offset);
    }

    return out;
  }

  Uint8List finalizeTag();

  void initParameters(CipherParameters parameters);

  @override
  void init(bool forEncryption, covariant ParametersWithIVAndAad params) {
    _encrypting = forEncryption;
    _aad = params.aad;
    _iv = params.iv;
    initParameters(params.parameters);
  }

  static bool _compareList(List a, List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

class AesCbcAuthenticatedCipherWithHash
    extends BlockCipherWithAuthenticationTag {
  final BlockCipher _underlyingCipher = new PaddedBlockCipherImpl(
      new PKCS7Padding(), new CBCBlockCipher(new AESFastEngine()));

  final Mac _underlyingMac;

  AesCbcAuthenticatedCipherWithHash(this._underlyingMac);

  @override
  String get algorithmName =>
      "${_underlyingCipher.algorithmName}+${_underlyingMac.algorithmName}";

  @override
  int get blockSize => _underlyingCipher.blockSize;

  @override
  void initParameters(covariant KeyParameter params) {
    var key = params.key;

    var macKey =
        new Uint8List.view(key.buffer, key.offsetInBytes, key.length ~/ 2);
    var encKey =
        new Uint8List.view(key.buffer, key.offsetInBytes + key.length ~/ 2);

    _underlyingMac.init(new KeyParameter(macKey));
    _underlyingCipher.init(
        isEncrypting,
        new PaddedBlockCipherParameters(
            new ParametersWithIV(
              new KeyParameter(encKey),
              iv,
            ),
            null));
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    throw new UnsupportedError("Should not be called");
  }

  @override
  void reset() {
    throw new UnsupportedError("Should not be called");
  }

  Uint8List _hash;

  @override
  Uint8List processBlocks(Uint8List data) {
    var out = _underlyingCipher.process(data);

    var ciphertext = isEncrypting ? out : data;

    var hashInput =
        new Uint8List(aad.length + iv.length + ciphertext.length + 8);

    var al = aad.length * 8;
    hashInput.setAll(0, aad);
    hashInput.setAll(aad.length, iv);
    hashInput.setAll(aad.length + iv.length, ciphertext);
    for (var i = hashInput.length - 1; i > (hashInput.length - 8); i--) {
      hashInput[i] = al % 256;
      al >>= 8;
    }

    _hash = _underlyingMac.process(hashInput);

    return out;
  }

  @override
  Uint8List finalizeTag() =>
      new Uint8List.view(_hash.buffer, _hash.offsetInBytes, tagLength);

  @override
  int get tagLength => _underlyingMac.macSize ~/ 2;
}

class AESKeyWrap implements BlockCipher {
  final BlockCipher _underlyingCipher = new AESFastEngine();

  @override
  String get algorithmName => "AESWrap";

  @override
  int get blockSize => 8;

  static final Uint8List _iv = new Uint8List.fromList([
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
  ]);
  bool _encrypting;

  @override
  void init(bool forEncryption, covariant KeyParameter params) {
    _encrypting = forEncryption;
    _underlyingCipher.init(forEncryption, params);
  }

  Uint8List wrap(Uint8List data) {
    var n = data.length ~/ 8;

    var r = new Uint8List.fromList(data);

    var a = new Uint8List(16);

    var b = new Uint8List(16);
    var b64 = new ByteData.view(b.buffer);

    a.setAll(0, _iv);

    for (var j = 0; j <= 5; j++) {
      for (var i = 0; i < n; i++) {
        var t = n * j + i + 1;

        a.setAll(8, r.skip(i * 8).take(8));

        _underlyingCipher.processBlock(a, 0, b, 0);

        b64.setInt64(0, b64.getInt64(0) ^ t);
        a.setAll(0, b.take(8));
        r.setAll(i * 8, b.skip(8));
      }
    }

    var c = new Uint8List(n * 8 + 8);
    c.setAll(0, a.take(8));
    c.setAll(8, r);

    return c;
  }

  Uint8List unwrap(Uint8List data) {
    var n = data.length ~/ 8 - 1;

    var a = new Uint8List(16);
    a.setAll(0, data.take(8));
    var a64 = new ByteData.view(a.buffer);

    var b = new Uint8List(16);

    var r = new Uint8List(n * 8);
    r.setAll(0, data.skip(8));

    for (var j = 5; j >= 0; j--) {
      for (var i = n - 1; i >= 0; i--) {
        var t = n * j + i + 1;

        a64.setInt64(0, a64.getInt64(0) ^ t);
        a.setAll(8, r.skip(i * 8).take(8));

        _underlyingCipher.processBlock(a, 0, b, 0);
        a.setAll(0, b.take(8));
        r.setAll(i * 8, b.skip(8));
      }
    }

    for (var i = 0; i < 8; i++) {
      if (_iv[i] != a[i]) {
        throw "Invalid "; // TODO
      }
    }
    return r;
  }

  @override
  Uint8List process(Uint8List data) {
    if (data.length % 8 != 0) {
      throw ArgumentError("Input data should be a multiple of 64 bits.");
    }

    if (_encrypting) {
      return wrap(data);
    } else {
      return unwrap(data);
    }
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    throw new UnsupportedError("Should not be called.");
  }

  @override
  void reset() {
    throw new UnsupportedError("Should not be called.");
  }
}
