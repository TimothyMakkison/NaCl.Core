namespace NaCl.Core.Benchmarks
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using Base;
    using Internal;

    using BenchmarkDotNet.Attributes;
    using Xunit;
    using static NaCl.Core.Tests.Vectors.WycheproofVector.TestGroup;

    [BenchmarkCategory("Stream Cipher")]
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn, HtmlExporter]
    public class ChaCha20Benchmark
    {
        private static readonly Random rnd = new Random(42);

        private Memory<byte> key;
        private Memory<byte> nonce;
        private Memory<byte> message;
        private Memory<byte> cipherText;
        private ChaCha20 cipher;

        [Params(
            (int)1E+2,  // 100 bytes
            (int)1E+3,  // 1 000 bytes = 1 KB
            (int)1E+5  // 100 000 bytes = 100 KB
            )] // 10 000 000 b
        public int Size { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key.Span);

            nonce = new byte[12];
            rnd.NextBytes(nonce.Span);

            message = new byte[Size];
            rnd.NextBytes(message.Span);

            cipher = new ChaCha20(key, 0);

            cipherText = new byte[Size];
            new ChaCha20(key, 0).Encrypt(message.Span, nonce.Span, cipherText.Span);
        }

        [Benchmark]
        [BenchmarkCategory("Encryption")]
        public void Encrypt()
        {
            var localCipherText = new byte[message.Length];
            cipher.Encrypt(message.Span, nonce.Span, localCipherText);
        }

        [Benchmark]
        [BenchmarkCategory("Decryption")]
        //[ArgumentsSource(nameof(TestVectors))]
        public void Decrypt()
        {
            var plaintext = new byte[Size];
            cipher.Decrypt(cipherText.Span, nonce.Span, plaintext);
        }

        public IEnumerable<object> TestVectors()
        {
            //foreach (var test in Tests.Rfc8439TestVector.Rfc8439TestVectors)
            //    yield return test;

            yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[0];
            yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[1];
            yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[2];
            yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[3];
            yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[4];
            yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[5];
            yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[6];
            yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[7];
        }

        // TODO: Use the encrypt value (from Encrypt method) to benchmark decryption
        //[Benchmark]
        //[BenchmarkCategory("Decryption")]
        //public byte[] Decrypt(byte[] ciphertext) => cipher.Decrypt(ciphertext);
    }
}
