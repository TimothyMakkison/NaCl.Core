﻿namespace NaCl.Core.Benchmarks
{
    using System;
    using System.Collections.Generic;

    using Base;

    using BenchmarkDotNet.Attributes;

    [BenchmarkCategory("Stream Cipher")]
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
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
      )] // 10 000 000 bytes = 10 MB
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

            cipherText = new byte[Size];
            var c = new ChaCha20(key, 0);
            c.Encrypt(message.Span, nonce.Span, cipherText.Span);

            cipher = new ChaCha20(key, 0);
        }

        [Benchmark]
        [BenchmarkCategory("Encryption")]
        public void Encrypt()
        {
            var ciphertext = new byte[message.Length];
            cipher.Encrypt(message.Span, nonce.Span, ciphertext);
        }

        [Benchmark]
        [BenchmarkCategory("Decryption")]
        public void Decrypt()
        {
            var plaintext = new byte[cipherText.Length];
            cipher.Decrypt(cipherText.Span, nonce.Span, plaintext);
        }

        //[Benchmark]
        //[BenchmarkCategory("Decryption")]
        //[ArgumentsSource(nameof(TestVectors))]
        //public void Decrypt(Tests.Vectors.Rfc8439TestVector test)
        //{
        //    var plaintext = new byte[test.CipherText.Length];
        //    var cipher = new ChaCha20(test.Key, test.InitialCounter);
        //    cipher.Decrypt(test.CipherText, test.Nonce, plaintext);
        //}

        //public IEnumerable<object> TestVectors()
        //{
        //    //foreach (var test in Tests.Rfc8439TestVector.Rfc8439TestVectors)
        //    //    yield return test;

        //    yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[0];
        //    yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[1];
        //    yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[2];
        //    yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[3];
        //    yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[4];
        //    yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[5];
        //    yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[6];
        //    yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[7];
        //}
    }
}
