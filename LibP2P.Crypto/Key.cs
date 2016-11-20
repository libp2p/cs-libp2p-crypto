using System;
using System.Linq;
using Org.BouncyCastle.Utilities.Encoders;

namespace LibP2P.Crypto
{
    public abstract class Key : IEquatable<Key>
    {
        public abstract KeyType Type { get; }
        public abstract byte[] Bytes { get; }

        private byte[] _hash;
        public byte[] Hash => _hash ?? (_hash = Utils.Hash(Bytes));

        public override string ToString() => Hex.ToHexString(Hash);

        public bool Equals(Key other) => other != null && Bytes.SequenceEqual(other.Bytes);
    }
}
