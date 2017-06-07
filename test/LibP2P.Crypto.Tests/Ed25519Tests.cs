using System.Text;
using Xunit;

namespace LibP2P.Crypto.Tests
{
    public class Ed25519Tests
    {
        [Fact]
        public void TestBasicSignAndVerify()
        {
            var pair = KeyPair.Generate(KeyType.Ed25519);
            var data = Encoding.UTF8.GetBytes("hello! and welcome to some awesome crypto primitives");

            var sig = pair.PrivateKey.Sign(data);
            var ok = pair.PublicKey.Verify(data, sig);
            Assert.True(ok);

            data[0] ^= data[0];
            ok = pair.PublicKey.Verify(data, sig);
            Assert.False(ok);
        }

        [Fact]
        public void TestSignZero()
        {
            var pair = KeyPair.Generate(KeyType.Ed25519);
            var data = new byte[] {};

            var sig = pair.PrivateKey.Sign(data);
            var ok = pair.PublicKey.Verify(data, sig);

            Assert.True(ok);
        }

        [Fact]
        public void TestMarshalLoop()
        {
            var pair = KeyPair.Generate(KeyType.Ed25519);

            var privB = pair.PrivateKey.Bytes;
            var privNew = PrivateKey.Unmarshal(privB);

            Assert.Equal(pair.PrivateKey, privNew);
            Assert.Equal(privNew, pair.PrivateKey);

            var pubB = pair.PublicKey.Bytes;
            var pubNew = PublicKey.Unmarshal(pubB);

            Assert.Equal(pair.PublicKey, pubNew);
            Assert.Equal(pubNew, pair.PublicKey);
        }

    }
}
