part of '../../algorithms.dart';

final class EcdhKeyAgreementAlgorithm extends KeyAgreementAlgorithm {
  const EcdhKeyAgreementAlgorithm() : super();

  @override
  bool operator ==(Object other) => other is EcdhKeyAgreementAlgorithm;

  @override
  int get hashCode => (EcdhKeyAgreementAlgorithm).hashCode;
}

final class X25519KeyAgreementAlgorithm extends KeyAgreementAlgorithm {
  const X25519KeyAgreementAlgorithm() : super();

  @override
  bool operator ==(Object other) => other is X25519KeyAgreementAlgorithm;

  @override
  int get hashCode => (X25519KeyAgreementAlgorithm).hashCode;
}
