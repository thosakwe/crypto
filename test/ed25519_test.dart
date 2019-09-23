import 'package:crypto/crypto.dart';
import 'package:test/test.dart';

void main() {
  test('checkparams', () {
    expect(Ed25519.b, greaterThanOrEqualTo(10));
    expect(8 * Ed25519.H("hash input".codeUnits).length, 2 * Ed25519.b);
    expect(Ed25519.expmod(BigInt.two, Ed25519.q - BigInt.one, Ed25519.q),
        BigInt.one);
    expect(Ed25519.l, greaterThanOrEqualTo(BigInt.two.pow(Ed25519.b - 4)));
    expect(Ed25519.l, lessThanOrEqualTo(BigInt.two.pow(Ed25519.b - 3)));
    expect(
        Ed25519.expmod(
            Ed25519.d, (Ed25519.q - BigInt.one) ~/ BigInt.two, Ed25519.q),
        Ed25519.q - BigInt.one);
    expect(Ed25519.expmod(Ed25519.I, BigInt.two, Ed25519.q),
        Ed25519.q - BigInt.one);
    expect(Ed25519.isoncurve(Ed25519.B), isTrue);
    expect(Ed25519.scalarmult(Ed25519.B, Ed25519.l), [BigInt.zero, BigInt.one]);
  });
}
