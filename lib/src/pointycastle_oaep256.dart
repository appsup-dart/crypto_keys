import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';
import 'package:pointycastle/src/registry/registry.dart';
import 'package:pointycastle/src/impl/base_asymmetric_block_cipher.dart';

class OAEP256Encoding extends BaseAsymmetricBlockCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      AsymmetricBlockCipher,
      '/OAEP-256',
      (_, final Match match) => () {
            var underlyingCipher = AsymmetricBlockCipher(match.group(1)!);
            return OAEP256Encoding(underlyingCipher);
          });

  Digest hash = SHA256Digest();
  late Digest mgf1Hash;
  Uint8List defHash = Uint8List(SHA256Digest().digestSize);

  final AsymmetricBlockCipher _engine;
  late SecureRandom _random;
  late bool _forEncryption;

  OAEP256Encoding(this._engine) {
    SHA256Digest().doFinal(defHash, 0);
  }

  @override
  String get algorithmName => '${_engine.algorithmName}/OAEP-256';

  @override
  void reset() {}

  Uint8List _seed() {
    var random = Random.secure();
    var seeds = <int>[];
    for (var i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    return Uint8List.fromList(seeds);
  }

  // for compat cleaner translation from java source
  Uint8List _arraycopy(
      Uint8List src, int srcPos, Uint8List dest, int destPos, int length) {
    dest.setRange(
        destPos, destPos + length, src.sublist(srcPos, srcPos + length));
    return dest;
  }

  @override
  void init(bool forEncryption, CipherParameters params) {
    AsymmetricKeyParameter akparams;
    mgf1Hash = hash;
    if (params is ParametersWithRandom) {
      var paramswr = params;
      _random = paramswr.random;
      akparams = paramswr.parameters as AsymmetricKeyParameter<AsymmetricKey>;
    } else {
      _random = FortunaRandom();
      _random.seed(KeyParameter(_seed()));
      akparams = params as AsymmetricKeyParameter<AsymmetricKey>;
    }
    _engine.init(forEncryption, akparams);
    _forEncryption = forEncryption;
  }

  @override
  int get inputBlockSize {
    var baseBlockSize = _engine.inputBlockSize;
    if (_forEncryption) {
      return baseBlockSize - 1 - 2 * defHash.length;
    } else {
      return baseBlockSize;
    }
  }

  @override
  int get outputBlockSize {
    var baseBlockSize = _engine.outputBlockSize;
    if (_forEncryption) {
      return baseBlockSize;
    } else {
      return baseBlockSize - 1 - (2 * defHash.length);
    }
  }

  @override
  int processBlock(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    if (_forEncryption) {
      return _encodeBlock(inp, inpOff, len, out, outOff);
    } else {
      return _decodeBlock(inp, inpOff, len, out, outOff);
    }
  }

  int _encodeBlock(
      Uint8List inp, int inpOff, int inpLen, Uint8List out, int outOff) {
    if (inpLen > inputBlockSize) {
      throw ArgumentError('Input data too large');
    }

    var block = Uint8List(inputBlockSize + 1 + 2 * defHash.length);

    //
    // copy in the message
    //
    // block.setRange(inpOff, block.length - inpLen, inp.sublist(inpLen));
    block = _arraycopy(inp, inpOff, block, block.length - inpLen, inpLen);

    //
    // add sentinel
    //
    block[block.length - inpLen - 1] = 0x01;

    //
    // as the block is already zeroed - there's no need to add PS (the >= 0 pad of 0)
    //

    //
    // add the hash of the encoding params.
    //
    block = _arraycopy(defHash, 0, block, defHash.length, defHash.length);

    //
    // generate the seed.
    //
    var seed = _random.nextBytes(defHash.length);

    //
    // mask the message block.
    //
    var mask = _maskGeneratorFunction1(
        seed, 0, seed.length, block.length - defHash.length);
    for (var i = defHash.length; i != block.length; i++) {
      block[i] ^= mask[i - defHash.length];
    }

    //
    // add in the seed
    //
    block = _arraycopy(seed, 0, block, 0, defHash.length);

    //
    // mask the seed.
    //
    mask = _maskGeneratorFunction1(
        block, defHash.length, block.length - defHash.length, defHash.length);
    for (var i = 0; i != defHash.length; i++) {
      block[i] ^= mask[i];
    }

    return _engine.processBlock(block, 0, block.length, out, outOff);
  }

  int _decodeBlock(
      Uint8List inp, int inpOff, int inpLen, Uint8List out, int outOff) {
    var block = Uint8List(_engine.inputBlockSize);
    var len = _engine.processBlock(inp, inpOff, inpLen, block, 0);
    block = block.sublist(0, len);

    var wrongData = (block.length < (2 * defHash.length) + 1);

    if (block.length <= block.length) {
      block = _arraycopy(
          block, 0, block, block.length - block.length, block.length);
    } else {
      block = _arraycopy(block, 0, block, 0, block.length);
      wrongData = true;
    }

    //
    // unmask the seed.
    //
    var mask = _maskGeneratorFunction1(
        block, defHash.length, block.length - defHash.length, defHash.length);
    for (var i = 0; i != defHash.length; i++) {
      block[i] ^= mask[i];
    }

    //
    // unmask the message block.
    //
    mask = _maskGeneratorFunction1(
        block, 0, defHash.length, block.length - defHash.length);

    for (var i = defHash.length; i != block.length; i++) {
      block[i] ^= mask[i - defHash.length];
    }

    //
    // check the hash of the encoding params.
    // long check to try to avoid this been a source of a timing attack.
    //
    var defHashWrong = false;

    for (var i = 0; i != defHash.length; i++) {
      if (defHash[i] != block[defHash.length + i]) {
        defHashWrong = true;
      }
    }

    //
    // find the data block
    //
    var start = block.length;
    for (var index = 2 * defHash.length; index != block.length; index++) {
      if ((block[index] != 0) & (start == block.length)) {
        start = index;
      }
    }

    var dataStartWrong = (start > (block.length - 1)) | (block[start] != 1);
    start++;

    if (defHashWrong | wrongData | dataStartWrong) {
      block.fillRange(0, block.length, 0);
      throw ArgumentError('data wrong');
    }

    //
    // extract the data block
    //
    var output = Uint8List(block.length - start);
    output = _arraycopy(block, start, output, 0, output.length);

    var rlen = (block.length - start);
    out.setRange(0, rlen, block.sublist(start));
    return rlen;
  }

  /// int to octet string.
  Uint8List _ItoOSP(int i, Uint8List sp) {
    sp[0] = i >> 24;
    sp[1] = i >> 16;
    sp[2] = i >> 8;
    sp[3] = i >> 0;
    return sp;
  }

  /// mask generator function, as described in PKCS1v2.
  Uint8List _maskGeneratorFunction1(
      Uint8List Z, int zOff, int zLen, int length) {
    var mask = Uint8List(length);
    var hashBuf = Uint8List(mgf1Hash.digestSize);
    var C = Uint8List(4);
    var counter = 0;
    mgf1Hash.reset();

    while (counter < (length / hashBuf.length).floor()) {
      _ItoOSP(counter, C);
      mgf1Hash.update(Z, zOff, zLen);
      mgf1Hash.update(C, 0, C.length);
      mgf1Hash.doFinal(hashBuf, 0);
      mask = _arraycopy(
          hashBuf, 0, mask, counter * hashBuf.length, hashBuf.length);
      counter++;
    }

    if ((counter * hashBuf.length) < length) {
      _ItoOSP(counter, C);
      mgf1Hash.update(Z, zOff, zLen);
      mgf1Hash.update(C, 0, C.length);
      mgf1Hash.doFinal(hashBuf, 0);
      mask = _arraycopy(hashBuf, 0, mask, counter * hashBuf.length,
          mask.length - (counter * hashBuf.length));
    }
    return mask;
  }
}
