using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecureHashAlgorithms;

namespace RSAImplementation
{
    public class EMEOAEP
    {
        private SHA hashAlgo = new SHA256();
        public byte[] Encode(byte[] M, int k)
        {
            var L = new byte[] { };
            int hLen = hashAlgo.OutputLength / 8;
            int mLen = M.Length;
            if (mLen > k - 2 * hLen - 2)
                throw new Exception("message too long.");
            var lHash = hashAlgo.ComputeHash(L);
            var PS = new byte[k - mLen - 2 * hLen - 2];
            var DB = lHash.Concat(PS).Concat(new byte[] { 1 }).Concat(M).ToArray();
            var rd = new Random();
            var seed = new byte[hLen];
            rd.NextBytes(seed);
            var dbMask = seed.MGF(k - hLen - 1, hashAlgo);
            var maskedDB = (DB.OS2IP() ^ dbMask.OS2IP()).I2OSP(DB.Length);
            var seedMask = maskedDB.MGF(hLen, hashAlgo);
            var maskedSeed = (seed.OS2IP() ^ seedMask.OS2IP()).I2OSP(seed.Length);
            var EM = new byte[1] { 0 }.Concat(maskedSeed).Concat(maskedDB).ToArray();
            return EM;
        }

        public byte[] Decode(byte[] EM, int k)
        {
            var L = new byte[] { };
            int hLen = hashAlgo.OutputLength / 8;
            if (k < 2 * hLen + 2)
                throw new Exception("decryption error.");

            var maskedSeed = EM.Skip(1).Take(hLen).ToArray();
            var maskedDB = EM.Skip(hLen + 1).Take(k - hLen - 1).ToArray();
            var seedMask = maskedDB.MGF(hLen, hashAlgo);
            var seed = (maskedSeed.OS2IP() ^ seedMask.OS2IP()).I2OSP(maskedSeed.Length);
            var dbMask = seed.MGF(k - hLen - 1, hashAlgo);
            var DB = (maskedDB.OS2IP() ^ dbMask.OS2IP()).I2OSP(maskedDB.Length);
            var lHash = hashAlgo.ComputeHash(L);
            var lHash2 = DB.Take(hLen).ToArray();
            if (Convert.ToHexString(lHash) != Convert.ToHexString(lHash2))
                throw new Exception("decryption error.");
            var splitIndex = DB.Skip(hLen).ToList().IndexOf(1);
            if (splitIndex == -1)
                throw new Exception("decryption error.");
            var M = DB.Skip(splitIndex + hLen + 1).ToArray();
            return M;
        }

    }
}
