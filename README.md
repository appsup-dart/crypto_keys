
[![Build Status](https://travis-ci.org/appsup-dart/crypto_keys.svg?branch=master)](https://travis-ci.org/appsup-dart/crypto_keys)
[:heart: sponsor](https://github.com/sponsors/rbellens)

A library for doing cryptographic signing/verifying and encrypting/decrypting.

It uses `pointycastle` under the hood, but exposes a more convenient 
api.



## Usage

### Choosing algorithms

You can choose algorithms in two ergonomic ways:

1. **Browsable catalog** (`package:crypto_keys/catalog.dart`) for discoverability
2. **Named constructors** on `*Algorithm` classes

```dart
import 'package:crypto_keys/catalog.dart';
import 'package:crypto_keys/crypto_keys.dart';

final hmacA = algorithms.signing.hmac.sha256;
final hmacB = SymmetricSigningAlgorithm.hmac(.sha256);

// Both values represent the same algorithm.
assert(hmacA == hmacB);
```

When a method expects a specific algorithm type, you can often use an
even shorter dot-shorthand expression:

```dart
final symmetricKey = SymmetricKey.generate(256);
final signer = symmetricKey.createSigner(.hmac(.sha256));
```

### Signing 

A simple usage example:

```dart
import 'package:crypto_keys/catalog.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'dart:typed_data';

main() {
  // Generate a random symmetric key pair
  var keyPair = SymmetricKeyPair.generate(256);

  // A key pair has a private and public key, possibly one of them is null, if
  // required info was not available when construction
  // The private key can be used for signing
  var privateKey = keyPair.privateKey;

  // Create a signer for the key using the HMAC/SHA-256 algorithm
  var signer = privateKey.createSigner(algorithms.signing.hmac.sha256);

  // Sign some content, to be integrity protected
  var content = "It's me, really me";
  var signature = signer.sign("It's me, really me".codeUnits);

  print("Signing '$content'");
  print("Signature: ${signature.data}");

  // The public key can be used for verifying the signature
  var publicKey = keyPair.publicKey;

  // Create a verifier for the key using the specified algorithm
  var verifier = publicKey.createVerifier(algorithms.signing.hmac.sha256);

  var verified =
      verifier.verify(new Uint8List.fromList(content.codeUnits), signature);
  if (verified)
    print("Verification succeeded");
  else
    print("Verification failed");
}
```

### Encryption

A simple usage example:

```dart
import 'package:crypto_keys/catalog.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'dart:typed_data';

main() {
  // Generate a new random symmetric key pair
  var keyPair = SymmetricKeyPair.generate(128);

  // Use the public key to create an encrypter with the AES/GCM algorithm
  var encrypter =
      keyPair.publicKey.createEncrypter(algorithms.encryption.aes.gcm);

  // Encrypt the content with an additional authentication data for integrity
  // protection
  var content = "A very secret text";
  var aad = "It is me";
  var v = encrypter.encrypt(new Uint8List.fromList(content.codeUnits),
      additionalAuthenticatedData: new Uint8List.fromList(aad.codeUnits));

  print("Encrypting '$content'");
  print("Ciphertext: ${v.data}");
  print("Authentication tag: ${v.authenticationTag}");

  // Use the private key to create the decrypter
  var decrypter =
      keyPair.privateKey.createDecrypter(algorithms.encryption.aes.gcm);

  // Decrypt and verify authentication tag
  var decrypted = decrypter.decrypt(v);

  print("Decrypted text: '${new String.fromCharCodes(decrypted)}'");
}

```

### Key Derivation

Key derivation means: "create a new cryptographic key from existing secret
material".

In practice, this is useful when:

- ECDH is used: you derive key material from your private key and someone
  else's public key, while the other person can derive the same key material
  from their private key and your public key, without transferring the key
  itself;
- you want to derive separate keys for different purposes from one shared
  secret (for example one key for encryption, another for something else);
- a protocol gives you context data (`otherInfo`) so both sides derive exactly
  the same key in a safe and predictable way.

Key derivation is exposed directly on the key material:

```dart
final otherInfo = ... // protocol-specific context bytes

final sharedSecretBytes = myEcPrivateKey.deriveSharedSecret(.ecdh(
  peerPublicKey: peerPublicEcKey,
));

final derived = sharedSecretBytes.deriveBits(.concatKdf(
  hash: .sha256,
  keyBitLength: 256,
  otherInfo: otherInfo,
));
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/appsup-dart/crypto_keys/issues


## Sponsor

Creating and maintaining this package takes a lot of time. If you like the result, please consider to [:heart: sponsor](https://github.com/sponsors/rbellens). 
With your support, I will be able to further improve and support this project.
Also, check out my other dart packages at [pub.dev](https://pub.dev/packages?q=publisher%3Aappsup.be).



