// Copyright (c) 2019, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.
import 'sha512.dart';

class Ed25519 {
  static const int b = 256;
  static final BigInt q = BigInt.two.pow(255) - BigInt.from(19);
  static final BigInt l = BigInt.two.pow(252) +
      BigInt.parse('27742317777372353535851937790883648493');

  static final BigInt d = BigInt.from(-121665) * inv(BigInt.from(121666));

  static final BigInt I =
      expmod(BigInt.two, (q - BigInt.one) ~/ BigInt.from(2), q);

  static final BigInt By = BigInt.from(4) * inv(BigInt.from(5));

  static final BigInt Bx = xrecover(By);

  static final List<BigInt> B = [Bx % q, By % q];

  static List<int> H(List<int> m) {
    return sha512.convert(m).bytes;
  }

  static BigInt expmod(BigInt b, BigInt e, BigInt m) {
    if (e == BigInt.zero) return BigInt.one;
    var t = (expmod(b, e ~/ BigInt.two, m).pow(2)) % m;
    if ((e & BigInt.one) != BigInt.zero) t = (t * b) % m;
    return t;
  }

  static BigInt inv(BigInt x) {
    return expmod(x, q - BigInt.two, q);
  }

  static BigInt xrecover(BigInt y) {
    var xx = (y * y - BigInt.one) * inv(d * y * y + BigInt.one);
    var x = expmod(xx, (q + BigInt.from(3)) ~/ BigInt.from(8), q);
    if ((x * x - xx) % q != BigInt.zero) {
      x = (x * I) % q;
    }
    if ((x % BigInt.two) != BigInt.zero) {
      x = q - x;
    }
    return x;
  }

  static List<BigInt> edwards(List<BigInt> P, List<BigInt> Q) {
    var x1 = P[0];
    var y1 = P[1];
    var x2 = Q[0];
    var y2 = Q[1];
    var x3 = (x1 * y2 + x2 * y1) * inv(BigInt.one + d * x1 * x2 * y1 * y2);
    var y3 = (y1 * y2 + x1 * x2) * inv(BigInt.one - d * x1 * x2 * y1 * y2);
    return [x3 % q, y3 % q];
  }

  List<BigInt> scalarmult(List<BigInt> P, BigInt e) {
    if (e == BigInt.zero) return [BigInt.zero, BigInt.one];
    var Q = scalarmult(P, e ~/ BigInt.two);
    Q = edwards(Q, Q);
    if ((e & BigInt.one) != BigInt.zero) Q = edwards(Q, P);
    return Q;
  }

  String encodeint(BigInt y) {
    var bits = List<BigInt>.generate(b, (i) => (y >> i) & BigInt.one);
    var charCodes = List<int>.generate(b ~/ 8, (i) {
      var sum =
          List.generate(8, (j) => bits[i * 8 + j] << j).reduce((a, b) => a + b);
      return sum.toInt();
    });
    return String.fromCharCodes(charCodes);
  }

  String encodepoint(List<BigInt> P) {
    var x = P[0];
    var y = P[1];
    var bits = List<BigInt>.generate(b - 1, (i) => (y >> i) & BigInt.one)
      ..add(x & BigInt.one);
    var charCodes = List<int>.generate(b ~/ 8, (i) {
      var sum =
          List.generate(8, (j) => bits[i * 8 + j] << j).reduce((a, b) => a + b);
      return sum.toInt();
    });
    return String.fromCharCodes(charCodes);
  }

  int bit(List<int> h, int i) {
    return (h[i ~/ 8] >> (i % 8)) & 1;
  }

  String publickey(List<int> sk) {
    var h = H(sk);
    var sum = List.generate(b - 5, (i) {
      i += 3;
      return BigInt.two.pow(i) * BigInt.from(bit(h, i));
    }).reduce((a, b) => a + b);
    var a = BigInt.two.pow(b - 2) + sum;
    var A = scalarmult(B, a);
    return encodepoint(A);
  }

  BigInt Hint(List<int> m) {
    var h = m;
    return List.generate(
            2 * b, (i) => BigInt.two.pow(i) * BigInt.from(bit(h, i)))
        .reduce((a, b) => a + b);
  }

  String signature(int m, List<int> sk, List<int> pk) {
    var h = H(sk);
    var a = BigInt.two.pow(b - 2) +
        List.generate(b - 5, (i) {
          i += 3;
          return BigInt.two.pow(i) * BigInt.from(bit(h, i));
        }).reduce((a, b) => a + b);
    var r = Hint(List.generate(b ~/ 4 - b ~/ 8, (i) {
      i += b ~/ 8;
      return h[i];
    })
      ..add(m));
    var R = scalarmult(B, r);
    var S = (r +
            Hint(encodepoint(R).codeUnits.followedBy(pk).toList()..add(m)) *
                a) %
        BigInt.one;
    return encodepoint(R) + encodeint(S);
  }

  bool isoncurve(List<BigInt> P) {
    var x = P[0];
    var y = P[1];
    return (-x * x + y * y - BigInt.one - d * x * x * y * y) % q == BigInt.zero;
  }

  BigInt decodeint(List<int> s) {
    return List.generate(b, (i) {
      return BigInt.two.pow(i) * BigInt.from(bit(s, i));
    }).reduce((a, b) => a + b);
  }

  List<BigInt> decodepoint(List<int> s) {
    var y = List.generate(b - 1, (i) {
      return BigInt.two.pow(i) * BigInt.from(bit(s, i));
    }).reduce((a, b) => a + b);
    var x = xrecover(y);
    if (x & BigInt.one != BigInt.from(bit(s, b - 1))) {
      x = q - x;
    }
    var P = [x, y];
    if (!isoncurve(P)) {
      throw FormatException("decoding point that is not on curve");
    }
    return P;
  }

  void checkvalid(List<int> s, int m, List<int> pk) {
    if (s.length != b / 4) {
      throw FormatException("signature length is wrong");
    }
    if (pk.length != b / 8) {
      throw FormatException("public-key length is wrong");
    }
    var R = decodepoint(s.take(b ~/ 8).toList());
    var A = decodepoint(pk);
    var S = decodeint(s.skip(b ~/ 8).take(b ~/ 4 - b ~/ 8).toList());
    var h = Hint(encodepoint(R).codeUnits.followedBy(pk).toList()..add(m));
    if (scalarmult(B, S) != edwards(R, scalarmult(A, h))) {
      throw FormatException("signature does not pass verification");
    }
  }
}
