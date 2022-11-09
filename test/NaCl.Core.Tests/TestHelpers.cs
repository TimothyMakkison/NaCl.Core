﻿namespace NaCl.Core.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using FluentAssertions;

public static class TestHelpers
{
    private static readonly Random _random = new Random();
    private static readonly object _sync = new object();

    private static int Random(int min, int max)
    {
        lock (_sync)
        {
            return _random.Next(min, max);
        }
    }

    public static void AssertEqualBytes(byte[] expected, byte[] actual)
        => BitConverter.ToString(actual).Should().Be(BitConverter.ToString(expected));

    public static ArraySegment<byte> Pad(this byte[] array)
        => array.Pad(Random(1, 100), Random(0, 50));

    private static ArraySegment<byte> Pad(this byte[] array, int paddingLeft, int paddingRight)
    {
        byte padByte = 0xE7;
        if (array.Length > 0)
        {
            if (array[0] == padByte)
                padByte++;
            if (array[array.Length - 1] == padByte)
                padByte++;
        }
        var resultBytes = Enumerable.Repeat(padByte, paddingLeft).Concat(array).Concat(Enumerable.Repeat(padByte, paddingRight)).ToArray();
        return new ArraySegment<byte>(resultBytes, paddingLeft, array.Length);
    }

    public static byte[] UnPad(this ArraySegment<byte> paddedData)
    {
        var padByte = paddedData.Array[0];
        if (padByte < 0xE7 || padByte > 0xE9)
            throw new ArgumentException("Padding invalid");

        for (var i = 0; i < paddedData.Offset; i++)
        {
            if (paddedData.Array[i] != padByte)
                throw new ArgumentException("Padding invalid");
        }
        for (var i = paddedData.Offset + paddedData.Count; i < paddedData.Array.Length; i++)
        {
            if (paddedData.Array[i] != padByte)
                throw new ArgumentException("Padding invalid");
        }
        return paddedData.ToArray();
    }

    public static int ReturnRandomPositiveNegative() => Random(0, 2) * 2 - 1;

    public static IEnumerable<byte[]> WithChangedBit(this byte[] array)
    {
        for (var i = 0; i < array.Length; i++)
        {
            for (var bit = 0; bit < 8; bit++)
            {
                var result = array.ToArray();
                result[i] ^= (byte)(1 << bit);
                yield return result;
            }
        }
    }

    public static uint[] ToUInt16Array(this byte[] source)
    {
        var decoded = new uint[source.Length / 4];
        Buffer.BlockCopy(source, 0, decoded, 0, source.Length);
        return decoded;
    }
}
