using System;
using System.Linq;
using System.Collections;
using SecureHashAlgorithms;

namespace RSAImplementation
{
    public class EMSAPSS
    {
        private SHA hashAlgo;
        public EMSAPSS(System.Security.Cryptography.HashAlgorithmName hashAlgorithmName)
        {
            hashAlgo = SHA.GetHashAlgorithm(hashAlgorithmName);
        }
        public byte[] Encode(byte[] M, int emBits)
        {
            if (M.Length > Math.Pow(2, 61) - 1)
                throw new Exception("message too long.");
            var mHash = hashAlgo.ComputeHash(M);
            return EncodeHash(mHash, emBits);
        }

        public byte[] EncodeHash(byte[] mHash, int emBits)
        {
            int emLen = (int)Math.Ceiling((double)emBits / 8);
            int hLen = hashAlgo.OutputLength / 8;
            int sLen = hLen;
            if (emLen < hLen + sLen + 2)
                throw new Exception("encoding error.");
            var salt = new byte[sLen];
            var rd = new Random();
            rd.NextBytes(salt);
            var M2 = new byte[8].Concat(mHash).Concat(salt).ToArray();
            var H = hashAlgo.ComputeHash(M2);
            var PS = new byte[emLen - sLen - hLen - 2];
            var DB = PS.Concat(new byte[] { 1 }).Concat(salt).ToArray();
            var dbMask = H.MGF(emLen - hLen - 1, hashAlgo);
            var maskedDB = (DB.OS2IP() ^ dbMask.OS2IP()).I2OSP(DB.Length);
            var bits = new BitArray(maskedDB);

            for (int i = 0; i < 8 * emLen - emBits; i++)
                bits[7 - i] = false;
            maskedDB = bits.ToByteArray();
            var EM = maskedDB.Concat(H).Concat(new byte[] { Convert.ToByte("bc", 16) }).ToArray();
            return EM;
        }

        public bool Verify(byte[] M, byte[] EM, int emBits)
        {
            if (M.Length > Math.Pow(2, 61) - 1)
                return false;
            var mHash = hashAlgo.ComputeHash(M);
            return VerifyHash(mHash, EM, emBits);
        }

        public bool VerifyHash(byte[] mHash, byte[] EM, int emBits)
        {
            var emLen = EM.Length;
            var hLen = hashAlgo.OutputLength / 8;
            var sLen = hLen;
            if (emLen < hLen + sLen + 2)
                return false;
            if (EM[emLen - 1].ToString("x2").ToLower() != "bc")
                return false;
            var maskedDB = EM.Take(emLen - hLen - 1).ToArray();
            var H = EM.Skip(emLen - hLen - 1).Take(hLen).ToArray();
            var bits = new BitArray(maskedDB);
            for (int i = 0; i < 8 * emLen - emBits; i++)
                if (bits[7 - i] == true)
                    return false;
            var dbMask = H.MGF(emLen - hLen - 1, hashAlgo);
            var DB = (maskedDB.OS2IP() ^ dbMask.OS2IP()).I2OSP(dbMask.Length);
            bits = new BitArray(DB);
            for (int i = 0; i < 8 * emLen - emBits; i++)
                bits[7 - i] = false;
            DB = bits.ToByteArray();
            if (DB.Take(emLen - hLen - sLen - 2).Any(b => b != 0))
                return false;
            if (DB[emLen - hLen - sLen - 2] != 1)
                return false;
            var salt = DB.Skip(DB.Length - sLen).Take(sLen);
            var M2 = new byte[8].Concat(mHash).Concat(salt).ToArray();
            var H2 = hashAlgo.ComputeHash(M2);
            if (Convert.ToHexString(H) != Convert.ToHexString(H2))
                return false;
            return true;
        }
    }
}
