using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ProtoBuf;
using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace LibP2P.Crypto
{
    internal static class Utils
    {
        private static readonly Lazy<SHA256> sha256 = new Lazy<SHA256>(SHA256.Create);

        public static byte[] Hash(byte[] bytes) => sha256.Value.ComputeHash(bytes);

        public static RsaKeyParameters UnmarshalPKIXPublicKey(string s) => UnmarshalPKIXPublicKey(Convert.FromBase64String(s));
        public static RsaKeyParameters UnmarshalPKIXPublicKey(byte[] bytes) => (RsaKeyParameters)PublicKeyFactory.CreateKey(bytes);

        public static byte[] MarshalPKIXPublicKey(RsaKeyParameters parameters) => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(parameters).GetDerEncoded();

        public static RsaPrivateCrtKeyParameters UnmarshalPKCS1PrivateKey(string s) => UnmarshalPKCS1PrivateKey(Convert.FromBase64String(s));
        public static RsaPrivateCrtKeyParameters UnmarshalPKCS1PrivateKey(byte[] bytes)
        {
            var obj = Asn1Object.FromByteArray(bytes);
            var pk = RsaPrivateKeyStructure.GetInstance(obj);

            return new RsaPrivateCrtKeyParameters(pk.Modulus, pk.PublicExponent, pk.PrivateExponent, pk.Prime1,
                pk.Prime2, pk.Exponent1, pk.Exponent2, pk.Coefficient);
        }

        public static byte[] MarshalPKCS1PrivateKey(RsaPrivateCrtKeyParameters p)
        {
            var key = new RsaPrivateKeyStructure(p.Modulus, p.PublicExponent, p.Exponent, p.P, p.Q, p.DP, p.DQ, p.QInv);
            var seq = Asn1Sequence.GetInstance(key);
            return seq.GetDerEncoded();
        }

        public static byte[] MarshalProtoBufContract<T>(T contract)
        {
            using (var stream = new MemoryStream())
            {
                Serializer.Serialize(stream, contract);
                return stream.ToArray();
            }
        }
    }
}