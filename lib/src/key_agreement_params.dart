import '../crypto_keys.dart';

/// Marker base class for key agreement params (ECDH, X25519).
sealed class KeyAgreementParams {
  const KeyAgreementParams();
}

/// Marker base class for EC key agreement params.
sealed class EcKeyAgreementParams extends KeyAgreementParams {
  const EcKeyAgreementParams();

  /// Shorthand factory for [EcdhKeyAgreementParams].
  static EcKeyAgreementParams ecdh({required EcPublicKey peerPublicKey}) =>
      EcdhKeyAgreementParams(peerPublicKey: peerPublicKey);
}

/// Marker base class for OKP key agreement (e.g. X25519).
sealed class OkpKeyAgreementParams extends KeyAgreementParams {
  const OkpKeyAgreementParams();

  /// Shorthand factory for [X25519KeyAgreementParams].
  static OkpKeyAgreementParams x25519({
    required X25519PublicKey peerPublicKey,
  }) => X25519KeyAgreementParams(peerPublicKey: peerPublicKey);
}

/// Parameters for ECDH key agreement.
class EcdhKeyAgreementParams extends EcKeyAgreementParams {
  final EcPublicKey peerPublicKey;

  const EcdhKeyAgreementParams({required this.peerPublicKey});
}

/// Parameters for X25519 (RFC 7748) key agreement.
class X25519KeyAgreementParams extends OkpKeyAgreementParams {
  final X25519PublicKey peerPublicKey;

  const X25519KeyAgreementParams({required this.peerPublicKey});
}
