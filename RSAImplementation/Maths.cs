using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace RSAImplementation
{
    public static class Maths
    {
        public static BigInteger ExtendEclidian(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
        {
            if (b == 0)
            {
                x = 1;
                y = 0;
                return a;
            }
            BigInteger q, r, d, x1 = 0, x2 = 1, y1 = 1, y2 = 0;
            while (b > 0)
            {
                q = a / b;
                r = a % b;
                x = x2 - q * x1;
                y = y2 - q * y1;
                a = b;
                b = r;
                x2 = x1;
                x1 = x;
                y2 = y1;
                y1 = y;
            }
            d = a;
            x = x2;
            y = y2;
            return d;
        }

        public static BigInteger ModInverse(this BigInteger a, BigInteger modulo)
        {
            // a.x+ modulo.y = 1
            BigInteger x, y;
            Maths.ExtendEclidian(a, modulo, out x, out y);
            if (x < 0)
                return x + modulo;
            return x;
        }

        public static bool MillerRabin(BigInteger n)
        {
            var rd = new Random();
            BigInteger m = n - 1;
            int k = 0;
            do
            {
                k++;
                m /= 2;
            } while (m % 2 == 0);

            BigInteger a = 2 + (int)(rd.Next() % (n - 4));
            BigInteger b = BigInteger.ModPow(a, m, n);
            if (b == 1)
                return true;
            for (int i = 0; i < k; i++)
            {
                if (b == n - 1)
                    return true;
                else
                    b = BigInteger.ModPow(b, 2, n);
            }
            return false;
        }

        public static bool IsPrime(this BigInteger n, int round = 20)
        {
            if (n == 0 || n == 1)
                return false;
            if (n == 2)
                return true;
            while (round > 0)
            {
                round--;
                if (!Maths.MillerRabin(n))
                    return false;
            }
            return true;
        }
    }
}
