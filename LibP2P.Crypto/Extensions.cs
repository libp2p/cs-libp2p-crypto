using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;

namespace LibP2P.Crypto
{
    internal static class Extensions
    {
        public static byte[] Slice(this byte[] bytes, int offset, int? count = null)
        {
            var result = new byte[count ?? bytes.Length - offset];
            Buffer.BlockCopy(bytes, offset, result, 0, result.Length);
            return result;
        }

        public static byte[] Append(this byte[] bytes, params byte[][] other)
        {
            var result = new byte[bytes.Length + other.Sum(b => b.Length)];
            Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
            var offset = bytes.Length;
            foreach (var b in other)
            {
                Buffer.BlockCopy(b, 0, result, offset, b.Length);
                offset += b.Length;
            }
            return result;
        }

        public static byte[] Sign(this ISigner signer, byte[] data)
        {
            signer.Reset();
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        public static bool Verify(this ISigner signer, byte[] data, byte[] signature)
        {
            signer.Reset();
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }
    }
}
