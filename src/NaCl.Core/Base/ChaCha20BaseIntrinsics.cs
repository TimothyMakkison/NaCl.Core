﻿#if INTRINSICS

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using NaCl.Core.Base.ChaChaIntrinsics;

namespace NaCl.Core.Base;

public static class ChaCha20BaseIntrinsics
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void ChaCha20(Span<uint> state, ReadOnlySpan<byte> input, Span<byte> output, ulong bytes)
    {
        if (!Sse3.IsSupported || !BitConverter.IsLittleEndian)
            throw new Exception("Error this vectorisation is not supported on this CPU");

        fixed (uint* x = state)
        fixed (byte* m_p = input, c_p = output)
        {
            var m = m_p;
            var c = c_p;

            if (Avx2.IsSupported && bytes >= 512)
            {
                ChaCha512.Process(x, ref m, ref c, ref bytes);
            }
            if (bytes >= 256)
            {
                ChaCha256.Process(x, ref m, ref c, ref bytes);
            }
            while (bytes >= 64)
            {
                ChaCha64.Process64(x, ref m, ref c, ref bytes);
            }
            if (bytes > 0)
            {
                ChaCha64.ProcessVarLength(x, ref m, ref c, ref bytes);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void HChaCha20(ReadOnlySpan<uint> state, Span<byte> subKey)
    {
        if (!Sse3.IsSupported || !BitConverter.IsLittleEndian)
            throw new Exception("Error this vectorisation is not supported on this CPU");

        fixed (uint* x = state)
        fixed (byte* sk = subKey)
        {
            ChaCha64.HChaCha20(x, sk);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void ChaCha20KeyStream(ReadOnlySpan<uint> state, Span<byte> output)
    {
        if (!Sse3.IsSupported || !BitConverter.IsLittleEndian)
            throw new Exception("Error this vectorisation is not supported on this CPU");

        fixed (byte* c = output)
        fixed (uint* x = state)
        {
            ChaCha64.KeyStream64(x, c);
        }
    }
}
#endif