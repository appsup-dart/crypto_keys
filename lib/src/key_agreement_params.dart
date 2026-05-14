import '../crypto_keys.dart';

/// Parameters for key agreement in this package.
///
/// Raw Diffie–Hellman uses [DiffieHellmanAgreementParams].
sealed class KeyAgreementParams {
  const KeyAgreementParams();
}

/// Parameters for key agreement on EC keys.
abstract mixin class EcKeyAgreementParams implements KeyAgreementParams {
  /// Builds [DiffieHellmanAgreementParams] for Weierstrass ECDH with [peerPublicKey].
  static EcKeyAgreementParams ecdh({required EcPublicKey peerPublicKey}) =>
      DiffieHellmanAgreementParams<EcPublicKey>(peerPublicKey: peerPublicKey);
}

/// Parameters for key agreement on Montgomery keys.
abstract mixin class MontgomeryKeyAgreementParams
    implements KeyAgreementParams {
  /// Builds [DiffieHellmanAgreementParams] for Montgomery RFC 7748 DH with [peerPublicKey].
  static MontgomeryKeyAgreementParams montgomeryDh({
    required MontgomeryPublicKey peerPublicKey,
  }) => DiffieHellmanAgreementParams<MontgomeryPublicKey>(
    peerPublicKey: peerPublicKey,
  );
}

/// Peer public key for a raw Diffie–Hellman agreement step.
///
/// [Peer] is the concrete [AgreementPublicKey] type for this agreement
/// ([EcPublicKey] with [EcPrivateKey], [MontgomeryPublicKey] with [MontgomeryPrivateKey]).
///
/// With a contextual type of [EcKeyAgreementParams] or [MontgomeryKeyAgreementParams],
/// use `deriveSharedSecret(.dh(peerPublicKey: …))`, or the generative constructor
/// `DiffieHellmanAgreementParams(peerPublicKey: …)`.
final class DiffieHellmanAgreementParams<Peer extends AgreementPublicKey>
    extends KeyAgreementParams
    with EcKeyAgreementParams, MontgomeryKeyAgreementParams {
  /// The peer’s public key for this agreement step.
  final Peer peerPublicKey;

  const DiffieHellmanAgreementParams({required this.peerPublicKey});
}
