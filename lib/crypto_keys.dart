library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:crypto_keys/src/operators/ed25519.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed25519_impl;
import 'package:x25519/x25519.dart' as x25519_impl;

import 'crypto_keys.dart';
import 'src/operators/ec.dart';
import 'src/operators/kdf.dart';
import 'src/operators/key_agreement.dart';
import 'src/operators/rsa.dart';
import 'src/operators/symmetric.dart';
import 'src/utils/pointycastle_ext.dart' as pc;
import 'src/utils/secure_random.dart';

export 'src/algorithms.dart'
    show
        Algorithm,
        Argon2idKdfAlgorithm,
        AsymmetricEncryptionAlgorithm,
        AsymmetricSigningAlgorithm,
        ConcatKdfAlgorithm,
        Curve,
        DigestAlgorithm,
        EcdhKeyAgreementAlgorithm,
        HkdfKdfAlgorithm,
        KdfAlgorithm,
        KeyAgreementAlgorithm,
        PasswordKdfAlgorithm,
        Pbkdf2KdfAlgorithm,
        SecretKdfAlgorithm,
        X25519KeyAgreementAlgorithm,
        EcSigningAlgorithm,
        Ed25519SigningAlgorithm,
        EncryptionAlgorithm,
        RsaEncryptionAlgorithm,
        RsaSigningAlgorithm,
        SigningAlgorithm,
        SymmetricEncryptionAlgorithm,
        SymmetricSigningAlgorithm;
export 'src/errors.dart';
export 'src/kdf_params.dart'
    show
        Argon2idKdfParams,
        ConcatKdfKdfParams,
        HkdfKdfParams,
        KdfParams,
        PasswordKdfParams,
        Pbkdf2KdfParams,
        SecretBytesKdfParams;
export 'src/key_agreement_params.dart'
    show
        EcdhKeyAgreementParams,
        EcKeyAgreementParams,
        KeyAgreementParams,
        OkpKeyAgreementParams,
        X25519KeyAgreementParams;
export 'src/algorithm_operations.dart';

part 'src/keys/ed25519.dart';
part 'src/keys/x25519.dart';
part 'src/keys/ec.dart';
part 'src/key_material.dart';
part 'src/operator.dart';
part 'src/keys/rsa.dart';
part 'src/keys/symmetric.dart';
