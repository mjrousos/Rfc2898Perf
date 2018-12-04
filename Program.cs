using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Repro
{
    class Program
    {
        public static void Main(string [] args)
        {
            var summary = BenchmarkRunner.Run<Benchmarks>();
        }
    }

    public class Benchmarks
    {
        private const string _password = "MyPassword";
        private readonly byte[] _salt = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D };
        private byte[] _cachedKey;
        private byte[] _cachedIV;
        private byte[] _clearBytes;

        [GlobalSetup]
        public void Setup()
        {
            _clearBytes = File.ReadAllBytes("IliadBook1.txt");

            var rfc2898DeriveBytes = new Rfc2898DeriveBytes(_password, _salt);
            _cachedKey = rfc2898DeriveBytes.GetBytes(32);
            _cachedIV = rfc2898DeriveBytes.GetBytes(16);

            ConfirmFunctionalEquivalence();
        }

        private void ConfirmFunctionalEquivalence()
        {
            var bytes1 = GenerateKeysAndEncryptData();
            var bytes2 = EncryptData();

            if (bytes1.Length != bytes2.Length)
            {
                throw new InvalidOperationException($"Methods created cipher byte[]s of different lengths: {bytes1.Length} - {bytes2.Length}");
            }

            for (var i = 0; i < bytes1.Length; i++)
            {
                if (bytes1[i] != bytes2[i])
                {
                    throw new InvalidOperationException("Cipher bytes do not match");
                }
            }

            Console.WriteLine("Algorithm equivalence confirmed");
        }

        [Benchmark(Baseline = true)]
        public byte[] GenerateKeysAndEncryptData()
        {
            var rfc2898DeriveBytes = new Rfc2898DeriveBytes(_password, _salt);
            var key = rfc2898DeriveBytes.GetBytes(32);
            var iv = rfc2898DeriveBytes.GetBytes(16);

            Rijndael alg = Rijndael.Create();
            alg.Key = key;
            alg.IV = iv;

            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, alg.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(_clearBytes, 0, _clearBytes.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }

        [Benchmark]
        public byte[] EncryptData()
        {
            if (_cachedKey == null || _cachedIV == null)
            {
                var rfc2898DeriveBytes = new Rfc2898DeriveBytes(_password, _salt);
                _cachedKey = rfc2898DeriveBytes.GetBytes(32);
                _cachedIV = rfc2898DeriveBytes.GetBytes(16);
            }

            Rijndael alg = Rijndael.Create();
            alg.Key = _cachedKey;
            alg.IV = _cachedIV;

            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, alg.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(_clearBytes, 0, _clearBytes.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }
    }
}
