using System;
using System.IO;
using ProtoBuf;

namespace LibP2P.Crypto
{
    public abstract class PrivateKey : Key
    {
        public abstract byte[] Sign(byte[] data);
        public abstract PublicKey GetPublic();

        public static PrivateKey Unmarshal(Stream stream)
        {
            var pb = Serializer.Deserialize<PrivateKeyContract>(stream);

            switch (pb.Type)
            {
                case KeyType.RSA:
                    return RsaPrivateKey.Unmarshal(pb.Data);
                case KeyType.Ed25519:
                    return Ed25519PrivateKey.Unmarshal(pb.Data);
                default:
                    throw new Exception("Bad key type");
            }
        }

        public static PrivateKey Unmarshal(byte[] data)
        {
            using (var stream = new MemoryStream(data))
            {
                return Unmarshal(stream);
            }
        }

        public byte[] Marshal() => Utils.MarshalProtoBufContract(new PrivateKeyContract { Type = Type, Data = MarshalKey() });

        protected abstract byte[] MarshalKey();
    }
}