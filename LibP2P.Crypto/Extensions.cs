using System;
using System.Linq;
using Org.BouncyCastle.Crypto;

namespace LibP2P.Crypto
{
    internal static class Extensions
    {
        /// <summary>
        /// Get a slice of the byte array
        /// </summary>
        /// <param name="bytes">input</param>
        /// <param name="offset">byte array offset</param>
        /// <param name="count">number of bytes to slice</param>
        /// <returns>byte slice</returns>
        public static byte[] Slice(this byte[] bytes, int offset, int? count = null)
        {
            var result = new byte[count ?? bytes.Length - offset];
            Buffer.BlockCopy(bytes, offset, result, 0, result.Length);
            return result;
        }

        /// <summary>
        /// Append byte arrays to given array
        /// </summary>
        /// <param name="bytes">input</param>
        /// <param name="other">arrays of byte to append</param>
        /// <returns>byte array of input and given arrays</returns>
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

        /// <summary>
        /// Sign bytes with the given signer
        /// </summary>
        /// <param name="signer">the signer to use</param>
        /// <param name="data">input data</param>
        /// <returns>signature</returns>
        public static byte[] Sign(this ISigner signer, byte[] data)
        {
            signer.Reset();
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        /// <summary>
        /// Verify data with the given signer and signature
        /// </summary>
        /// <param name="signer">the signer to use</param>
        /// <param name="data">input data</param>
        /// <param name="signature">signature</param>
        /// <returns>validity</returns>
        public static bool Verify(this ISigner signer, byte[] data, byte[] signature)
        {
            signer.Reset();
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }
    }
}
