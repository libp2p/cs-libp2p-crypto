using System;
using System.IO;
using System.Linq;
using ProtoBuf;

namespace LibP2P.Crypto
{
    public abstract class PublicKey : Key
    {
        public abstract bool Verify(byte[] data, byte[] signature);

        public static PublicKey Unmarshal(Stream stream)
        {
            var pb = Serializer.Deserialize<PublicKeyContract>(stream);
            switch (pb.Type)
            {
                case KeyType.RSA:
                    return RsaPublicKey.Unmarshal(pb.Data);
                case KeyType.Ed25519:
                    return new Ed25519PublicKey(pb.Data.Take(32).ToArray());
                default:
                    throw new Exception("Bad key type");
            }
        }

        public static PublicKey Unmarshal(byte[] data)
        {
            using (var stream = new MemoryStream(data))
            {
                return Unmarshal(stream);
            }
        }

        public byte[] Marshal() => Utils.MarshalProtoBufContract(new PublicKeyContract { Type = Type, Data = MarshalKey() });

        protected abstract byte[] MarshalKey();
    }
}