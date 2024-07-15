using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public sealed class AeadParameters
		: ICipherParameters
	{
		internal byte[] associatedText;
        internal ReadOnlyMemory<byte> nonce;
        internal KeyParameter key;
		internal int macSize;

        /**
         * Base constructor.
         *
         * @param key key to be used by underlying cipher
         * @param macSize macSize in bits
         * @param nonce nonce to be used
         */
        public AeadParameters(KeyParameter key, int macSize, ReadOnlyMemory<byte> nonce)
           : this(key, macSize, nonce, null)
        {
        }

        /**
		 * Base constructor.
		 *
		 * @param key key to be used by underlying cipher
		 * @param macSize macSize in bits
		 * @param nonce nonce to be used
		 * @param associatedText associated text, if any
		 */
		public AeadParameters(KeyParameter key, int macSize, ReadOnlyMemory<byte> nonce, byte[] associatedText)
		{
            this.key = key;
			this.nonce = nonce;
			this.macSize = macSize;
			this.associatedText = associatedText;
		}

		public KeyParameter Key
		{
			get { return key; }
		}

		public int MacSize
		{
			get { return macSize; }
		}

		public byte[] GetAssociatedText()
		{
			return associatedText;
		}

		public byte[] GetNonce()
		{
			return nonce.ToArray();
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> Nonce => nonce.Span;
#endif
    }
}
