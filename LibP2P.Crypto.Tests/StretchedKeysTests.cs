using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace LibP2P.Crypto.Tests
{
    [TestFixture]
    public class StretchedKeysTests
    {
        [Test]
        public void CanStretchKeys()
        {
            var ekeypair1 = EphemeralKeyPair.Generate("P-256");
            var ekeypair2 = EphemeralKeyPair.Generate("P-256");
            var secret1 = ekeypair1.GenerateSharedKey(ekeypair2.PublicKey);
            var secret2 = ekeypair2.GenerateSharedKey(ekeypair1.PublicKey);
            var stretched1 = StretchedKeys.Generate("AES-256", "SHA256", secret1);
            var stretched2 = StretchedKeys.Generate("AES-256", "SHA256", secret2);

            var raw = Encoding.UTF8.GetBytes("Hello world, this should be encrypted.");
            byte[] encoded = null;
            byte[] decoded = null;

            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;

                using (var encryptor = aes.CreateEncryptor(stretched1.Item1.CipherKey, stretched1.Item1.IV))
                using (var mac = HMAC.Create("HMACSHA256"))
                {
                    mac.Initialize();
                    mac.Key = stretched1.Item1.MacKey;
                    var data = encryptor.TransformFinalBlock(raw, 0, raw.Length);

                    encoded = data
                            .Concat(mac.ComputeHash(data, 0, data.Length))
                            .ToArray();
                }

                using (var decryptor = aes.CreateDecryptor(stretched2.Item1.CipherKey, stretched2.Item1.IV))
                using (var mac = HMAC.Create("HMACSHA256"))
                {
                    mac.Initialize();
                    mac.Key = stretched2.Item1.MacKey;
                    var mark = encoded.Length - (mac.HashSize/8);
                    var digest = encoded.Skip(mark).ToArray();
                    Assert.That(mac.ComputeHash(encoded, 0, mark), Is.EqualTo(digest));

                    decoded = decryptor.TransformFinalBlock(encoded, 0, mark);
                }
            }

            Assert.That(Encoding.UTF8.GetString(decoded), Is.EqualTo(Encoding.UTF8.GetString(raw)));
        }
    }
}
