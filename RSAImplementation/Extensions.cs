using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Collections;
using SecureHashAlgorithms;

namespace RSAImplementation
{
    public static class Extensions
    {
        public static BigInteger OS2IP(this byte[] p)
        {
            return new BigInteger(p, true, true);
        }

        public static byte[] I2OSP(this BigInteger i, int l = 0)
        {
            var I = i.ToByteArray(true, true);
            if (l == 0)
                return I;
            if (I.Length > l)
                throw new Exception("converting error.");
            if (I.Length < l)
                I = new byte[l - I.Length].Concat(I).ToArray();
            return I;
        }

        public static byte[] ToByteArray(this BitArray bits)
        {
            var bytes = new byte[bits.Length / 8];
            bits.CopyTo(bytes, 0);
            return bytes;
        }

        public static byte[] MGF(this byte[] Z, int l, SHA hashAlgo)
        {
            var T = Array.Empty<byte>();
            var hLen = hashAlgo.OutputLength / 8;
            int length = (int)Math.Ceiling((double)l / hLen);
            for (int i = 0; i < length; i++)
            {
                var C = Convert.ToUInt32(i).GetBytes();
                T = T.Concat(hashAlgo.ComputeHash(Z.Concat(C).ToArray())).ToArray();
            }
            return T.Take(l).ToArray();
        }
    }
}
