using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Security.Cryptography;
using System.Collections;
using System.Threading;
using SecureHashAlgorithms;

namespace RSAImplementation
{
    public class RSA : System.Security.Cryptography.RSA
    {
        private bool selectedP, selectedQ;
        private BigInteger p, q, n, phi, d, dp, dq, inq;
        private readonly BigInteger e = 65537;
        public string HashAlgorithm { get; }
        private RSAParameters parameters;
        private EMSAPSS pss;
        public override int KeySize { get; set; }

        public RSA() { }
        public RSA(int keySize)
        {
            KeySize = keySize;
            GenerateKeyPair();
        }

        private BigInteger RandomOdd(int bitLength)
        {
            if (bitLength % 8 != 0)
                throw new Exception($"bit-length must be divisible 8.");
            var bytes = new byte[bitLength / 8];
            var rd = new Random();
            rd.NextBytes(bytes);
            bytes[0] = (byte)rd.Next(192, 256);
            if (bytes[^1] % 2 == 0)
                bytes[^1]--;
            var num = bytes.OS2IP();
            return num;
        }

        private void RandomPQ()
        {
            int len = KeySize / 2;
            BigInteger prime = 0;
            var pqLimit = BigInteger.Pow(2, len - 100);
            int count = 0;
            while (!selectedP)
            {
                count++;
                prime = RandomOdd(len);
                if (prime.IsPrime() && !selectedP)
                {
                    selectedP = true;
                    p = prime;
                }
            }
            count = 0;
            while (!selectedQ)
            {
                count++;
                prime = RandomOdd(len);
                if (BigInteger.Abs(p - prime) > pqLimit && prime.IsPrime() && !selectedQ)
                {
                    selectedQ = true;
                    q = prime;
                }
            }
        }

        private void GenerateKeyPair()
        {
            Parallel.For(0, 4, (x, state) => { RandomPQ(); state.Break(); });
            n = p * q;
            phi = (p - 1) * (q - 1);
            d = e.ModInverse(phi);
            dp = d % (p - 1);
            dq = d % (q - 1);
            inq = q.ModInverse(p);
            parameters = new RSAParameters()
            {
                Exponent = e.I2OSP(),
                P = p.I2OSP(),
                Q = q.I2OSP(),
                Modulus = n.I2OSP(),
                D = d.I2OSP(),
                DP = dp.I2OSP(),
                DQ = dq.I2OSP(),
                InverseQ = inq.I2OSP()
            };
        }

        public byte[] Encrypt(byte[] M)
        {
            int k = KeySize / 8;
            var oaep = new EMEOAEP();
            var EM = oaep.Encode(M, k);
            var em = EM.OS2IP();
            var c = BigInteger.ModPow(em, e, n);
            var C = c.I2OSP(k);
            return C;
        }

        public byte[] Decrypt(byte[] C)
        {
            int k = KeySize / 8;
            if (k != C.Length)
                throw new Exception("decrypting error.");
            var c = C.OS2IP();
            var em = BigInteger.ModPow(c, d, n);
            var EM = em.I2OSP(k);
            var oaep = new EMEOAEP();
            var M = oaep.Decode(EM, k);
            return M;
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            return SHA.GetHashAlgorithm(hashAlgorithm).ComputeHash(data);
        }

        public override byte[] SignData(byte[] M, int offset, int count, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            var mHash = HashData(M, 0, M.Length, hashAlgorithm);
            return SignHash(mHash, hashAlgorithm, padding);
        }

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            var emsa = new EMSAPSS(hashAlgorithm);
            var emBits = KeySize - 1;
            var EM = emsa.EncodeHash(hash, emBits);
            var m = EM.OS2IP();
            var d = parameters.D.OS2IP();
            var n = parameters.Modulus.OS2IP();
            var s = BigInteger.ModPow(m, d, n);
            int k = (int)Math.Ceiling((double)emBits / 8);
            var S = s.I2OSP(k);
            Console.WriteLine(Convert.ToBase64String(S));
            return S;
        }

        public override bool VerifyData(byte[] M, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            var mHash = HashData(M, 0, M.Length, hashAlgorithm);
            return VerifyHash(mHash, signature, hashAlgorithm, padding);
        }

        public override bool VerifyHash(byte[] mHash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            pss = new EMSAPSS(hashAlgorithm);
            var s = signature.OS2IP();
            var e = parameters.Exponent.OS2IP();
            var n = parameters.Modulus.OS2IP();
            var m = BigInteger.ModPow(s, e, n);

            int emBits = KeySize - 1;
            int emLen = (int)Math.Ceiling((double)emBits / 8);
            var EM = m.I2OSP(emLen);
            return pss.VerifyHash(mHash, EM, emBits);
        }
        public override void ImportParameters(RSAParameters parameters)
        {
            KeySize = parameters.Modulus.Length * 8;
            this.parameters = parameters;
            n = parameters.Modulus.OS2IP();
            if (parameters.D != null && parameters.D.Length > 0)
            {
                p = parameters.P.OS2IP();
                q = parameters.Q.OS2IP();
                d = parameters.D.OS2IP();
                dp = parameters.DP.OS2IP();
                dq = parameters.DQ.OS2IP();
                inq = parameters.InverseQ.OS2IP();
            }
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            if (!includePrivateParameters)
            {
                return new RSAParameters()
                {
                    Exponent = parameters.Exponent,
                    Modulus = parameters.Modulus
                };
            }
            return new RSAParameters()
            {
                P = p.ToByteArray(true, true),
                Q = q.ToByteArray(true, true),
                D = d.ToByteArray(true, true),
                DP = dp.ToByteArray(true, true),
                DQ = dq.ToByteArray(true, true),
                InverseQ = inq.ToByteArray(true, true),
                Exponent = e.ToByteArray(true, true),
                Modulus = n.ToByteArray(true, true),
            };
        }
    }
}