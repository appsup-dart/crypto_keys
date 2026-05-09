library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:crypto_keys/src/operators/ed25519.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed25519_impl;

import 'src/algorithms.dart';
import 'src/digest_utils.dart';
import 'src/operators/ec.dart';
import 'src/operators/rsa.dart';
import 'src/operators/symmetric.dart';
import 'src/pointycastle_ext.dart' as pc;
import 'src/secure_random.dart';

export 'src/algorithms.dart'
    show
        AlgorithmIdentifier,
        AsymmetricEncryptionAlgorithmIdentifier,
        AsymmetricSigningAlgorithmIdentifier,
        CurveIdentifier,
        DerivationAlgorithmIdentifier,
        DigestAlgorithmIdentifier,
        EcSigningAlgorithmIdentifier,
        Ed25519SigningAlgorithmIdentifier,
        EncryptionAlgorithmIdentifier,
        Identifier,
        RsaEncryptionAlgorithmIdentifier,
        RsaSigningAlgorithmIdentifier,
        SigningAlgorithmIdentifier,
        SymmetricEncryptionAlgorithmIdentifier,
        SymmetricSigningAlgorithmIdentifier;
export 'src/errors.dart';

part 'src/ed25519_keys.dart';
part 'src/ec_keys.dart';
part 'src/keys.dart';
part 'src/key_derivation.dart';
part 'src/key_derivation_params.dart';
part 'src/operator.dart';
part 'src/rsa_keys.dart';
part 'src/symmetric_keys.dart';
