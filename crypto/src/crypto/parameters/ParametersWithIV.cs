using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers;
#endif

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithIV
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ParametersWithIV Create<TState>(ICipherParameters parameter, int ivLength, TState state,
            SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));
            if (ivLength < 0)
                throw new ArgumentOutOfRangeException(nameof(ivLength));

            var iv = new byte[ivLength];

            ParametersWithIV result = new ParametersWithIV(parameter, iv.AsMemory());
            action(iv, state);
            return result;
        }
#endif

        internal static ICipherParameters ApplyOptionalIV(ICipherParameters parameters, ReadOnlyMemory<byte>? iv)
        {
            return !iv.HasValue ? parameters : new ParametersWithIV(parameters, iv.Value);
        }

        private readonly ICipherParameters m_parameters;
        private readonly ReadOnlyMemory<byte> m_iv;


        public ParametersWithIV(ICipherParameters parameters, ReadOnlyMemory<byte> iv)
        {
            m_parameters = parameters;
            m_iv = iv;
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
//        public ParametersWithIV(ICipherParameters parameters, ReadOnlySpan<byte> iv)
//        {
//            // NOTE: 'parameters' may be null to imply key re-use
//            m_parameters = parameters;
//            m_iv = iv.ToArray();
//        }
//#endif

        private ParametersWithIV(ICipherParameters parameters, int ivLength)
        {
            if (ivLength < 0)
                throw new ArgumentOutOfRangeException(nameof(ivLength));

            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_iv = new byte[ivLength];
        }

        public void CopyIVTo(byte[] buf, int off, int len)
        {
            if (m_iv.Length != len)
                throw new ArgumentOutOfRangeException(nameof(len));

            m_iv.CopyTo(new Memory<byte>(buf, off, len));
        }

        public byte[] GetIV()
        {
            return m_iv.ToArray();
        }

        public int IVLength => m_iv.Length;

        public ICipherParameters Parameters => m_parameters;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> IV => m_iv.Span;
#endif
    }
}
