import 'package:crypto_keys/crypto_keys.dart';
import 'dart:typed_data';

void main() {
  // Generate a random symmetric key pair for HMAC signing.
  var keyPair = SymmetricKeyPair.generate(256);

  // A key pair has a private and public key, possibly one of them is null, if
  // required info was not available when construction
  // The private key can be used for signing
  var privateKey = keyPair.privateKey;

  // Create a signer for the key using the HMAC/SHA-256 algorithm
  var signer = privateKey.createSigner(.hmac(.sha256));

  // Sign some content, to be integrity protected
  var content = "It's me, really me";
  var signature = signer.sign("It's me, really me".codeUnits);

  print("Signing '$content'");
  print('Signature: ${signature.data}');

  // The public key can be used for verifying the signature
  var publicKey = keyPair.publicKey;

  // Create a verifier for the key using the specified algorithm
  var verifier = publicKey.createVerifier(.hmac(.sha256));

  var verified = verifier.verify(
    Uint8List.fromList(content.codeUnits),
    signature,
  );
  if (verified) {
    print('Verification succeeded');
  } else {
    print('Verification failed');
  }
}
