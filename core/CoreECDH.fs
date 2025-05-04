module CoreECDH

open Bytes
open System
open CoreKeys
open Org.BouncyCastle.Math
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Math.EC
open Org.BouncyCastle.Security

let secp256r1 =
    let p256 = BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
    let curve =
        FpCurve(p256,
                BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948", 10),
                BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16))
    let basepx = FpFieldElement(p256, BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16))
    let basepy = FpFieldElement(p256, BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16))
    let basep = curve.CreatePoint(basepx.ToBigInteger(), basepy.ToBigInteger())
    let dom = ECDomainParameters(curve, basep, BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10))
    (curve, dom, basep)

let getcurve =
    function
    | EC_PRIME ecp ->
        let p = BigInteger(ecp.ecp_prime, 10)
        let curve = FpCurve(p, BigInteger(ecp.ecp_a, 10), BigInteger(ecp.ecp_b, 16))
        let basep = curve.CreatePoint(BigInteger(ecp.ecp_gx, 16), BigInteger(ecp.ecp_gy, 16))
        let dom = ECDomainParameters(curve, basep, BigInteger(ecp.ecp_order, 10))
        (curve, dom, basep)

let ptlength =
    function
    | EC_PRIME ecp -> ecp.ecp_bytelen

let bytes_to_bigint (b : bytes) = BigInteger(1, cbytes b)

let bytes_of_bigint (b : BigInteger) (p:ecdhparams) =
    let rec pad (b:bytes) n =
        if n > 0 then pad ((abyte 0uy) @| b) (n-1)
        else b
    let cl = ptlength p.curve
    let b = abytes (b.ToByteArrayUnsigned())
    pad b (cl - length b)

let gen_key (p:ecdhparams) : (ecdhskey * ecdhpkey) =
    let curve, ecdom, basep = getcurve p.curve
    let ecparam = ECKeyGenerationParameters(ecdom, SecureRandom())
    let gen = ECKeyPairGenerator()
    gen.Init(ecparam)
    let keys = gen.GenerateKeyPair()
    let pk = keys.Public :?> ECPublicKeyParameters
    let sk = keys.Private :?> ECPrivateKeyParameters
    let q = pk.Q.Normalize()
    let x = q.AffineXCoord.ToBigInteger()
    let y = q.AffineYCoord.ToBigInteger()
    let pub = { ecx = bytes_of_bigint x p; ecy = bytes_of_bigint y p }
    let priv = abytes (sk.D.ToByteArrayUnsigned())
    (priv, pub)

let serialize (p:ecpoint) : bytes =
    abyte 4uy @| p.ecx @| p.ecy

let agreement (p:ecdhparams) (sk:ecdhskey) (pk:ecdhpkey) : bytes =
    let curve, ecdom, basep = getcurve p.curve
    let pubP = curve.CreatePoint(bytes_to_bigint pk.ecx, bytes_to_bigint pk.ecy)
    let mul = pubP.Multiply(bytes_to_bigint sk)
    let mulNorm = mul.Normalize()
    bytes_of_bigint (mulNorm.AffineXCoord.ToBigInteger()) p

let is_on_curve (p:ecdhparams) (e:ecpoint) : bool =
    try
        let curve, ecdom, basep = getcurve p.curve
        let X = bytes_to_bigint e.ecx
        let Y = bytes_to_bigint e.ecy
        if X.CompareTo(curve.Q) > 0 || Y.CompareTo(curve.Q) > 0 then false
        else
            let P = curve.CreatePoint(X, Y)
            not P.IsInfinity
    with _ -> false
