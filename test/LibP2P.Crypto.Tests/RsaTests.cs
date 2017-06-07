using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace LibP2P.Crypto.Tests
{
    public class RsaTests
    {
        [Fact]
        public void CanUnmarshalAndMarshalPublicKey_FromReferenceImpl()
        {
            var pub = "CAASXjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvNQkMgofMnx/cdtpSEDJAtq0lj/zFW+9214vau7moGaH2U7FTBVGY1mGYv7jZLZjgimiXS9isyCdOKJcJGTeBAgMBAAE=";
            var key = PublicKey.Unmarshal(Convert.FromBase64String(pub));
            var pub2 = Convert.ToBase64String(key.Bytes);

            Assert.Equal(pub2, pub);
        }

        [Fact]
        public void CanUnmarshalAndMarshalPrivateKey_FromReferenceImpl()
        {
            var priv = "CAASvgIwggE6AgEAAkEArzUJDIKHzJ8f3HbaUhAyQLatJY/8xVvvdteL2ru5qBmh9lOxUwVRmNZhmL+42S2Y4Ipol0vYrMgnTiiXCRk3gQIDAQABAkBWxKUelOY75/IXdKTaTzsT4WQOXiiIdOc6q7SPNrjTDkxnTs/yXhLAG+G7l6J0dHHgWwHPzjowfnuUoC7kj7WhAiEAxXtimqAbpFVGqw9V+omytlQay7xbhgQ9ip84y57SRDsCIQDjH+zNvrpv4ZOcWqUCrfNbib9KvSelhRLQhxckSWmjcwIhALk0sVIgrCvfigottM3lzAQxNnwyZ4d1fJ4AG4zjo4E3AiA4q16Kd2xNPht2h6dkY8K0tEnmfAvIYMuw/APqKecRwQIgXFWUc3F90BMoe7MhVHvizEuXks8ln3jZA6Ih9AwUixM=";
            var key = PrivateKey.Unmarshal(Convert.FromBase64String(priv));
            var priv2 = Convert.ToBase64String(key.Bytes);

            Assert.Equal(priv2, priv);
        }

        [Fact]
        public void CanUnmarshalPrivateKeyAndMarshalPublicKey_FromReferenceImpl()
        {
            var priv = "CAASvgIwggE6AgEAAkEArzUJDIKHzJ8f3HbaUhAyQLatJY/8xVvvdteL2ru5qBmh9lOxUwVRmNZhmL+42S2Y4Ipol0vYrMgnTiiXCRk3gQIDAQABAkBWxKUelOY75/IXdKTaTzsT4WQOXiiIdOc6q7SPNrjTDkxnTs/yXhLAG+G7l6J0dHHgWwHPzjowfnuUoC7kj7WhAiEAxXtimqAbpFVGqw9V+omytlQay7xbhgQ9ip84y57SRDsCIQDjH+zNvrpv4ZOcWqUCrfNbib9KvSelhRLQhxckSWmjcwIhALk0sVIgrCvfigottM3lzAQxNnwyZ4d1fJ4AG4zjo4E3AiA4q16Kd2xNPht2h6dkY8K0tEnmfAvIYMuw/APqKecRwQIgXFWUc3F90BMoe7MhVHvizEuXks8ln3jZA6Ih9AwUixM=";
            var privkey = PrivateKey.Unmarshal(Convert.FromBase64String(priv));
            var pubkey = privkey.GetPublic();
            var pub = Convert.ToBase64String(pubkey.Bytes);

            Assert.Equal(pub, "CAASXjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvNQkMgofMnx/cdtpSEDJAtq0lj/zFW+9214vau7moGaH2U7FTBVGY1mGYv7jZLZjgimiXS9isyCdOKJcJGTeBAgMBAAE=");
        }

        [Fact]
        public void StressTestRsaKeys()
        {
            for (var i = 0; i < 100; i++)
            {
                var pair = KeyPair.Generate(KeyType.RSA, 512);

                TestKeySignature(pair.PrivateKey);
                TestKeyEncoding(pair.PrivateKey);
                TestKeyEquals(pair.PrivateKey);
                TestKeyEquals(pair.PublicKey);
            }
        }

        [Theory]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(2048)]
        //[InlineData(4096)]
        public void TestRsaKeys(int bits)
        {
            var pair = KeyPair.Generate(KeyType.RSA, bits);

            TestKeySignature(pair.PrivateKey);
            TestKeyEncoding(pair.PrivateKey);
            TestKeyEquals(pair.PrivateKey);
            TestKeyEquals(pair.PublicKey);
        }

        private void TestKeyEquals(Key key)
        {
            var kb = key.Bytes;

            Assert.Equal(key, key);
            Assert.Equal(key, new MockKey(KeyType.RSA, kb));
        }

        private class MockKey : Key
        {
            public MockKey(KeyType type, byte[] bytes)
            {
                Type = type;
                Bytes = bytes;
            }

            public override KeyType Type { get; }
            public override byte[] Bytes { get; }
        }

        private void TestKeyEncoding(PrivateKey sk)
        {
            var skbm = sk.Marshal();
            var sk2 = PrivateKey.Unmarshal(skbm);
            var skbm2 = sk2.Marshal();
            Assert.Equal(skbm, skbm2);

            var pk = sk.GetPublic();
            var pkbm = pk.Marshal();
            var pk2 = PublicKey.Unmarshal(pkbm);
            var pkbm2 = pk2.Marshal();
            Assert.Equal(pkbm, pkbm2);
        }

        private void TestKeySignature(PrivateKey sk)
        {
            var pk = sk.GetPublic();

            var text = new byte[16];
            new Random().NextBytes(text);

            var sig = sk.Sign(text);
            var valid = pk.Verify(text, sig);

            Assert.True(valid);
        }
    }
}
