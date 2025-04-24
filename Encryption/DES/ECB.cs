namespace DESEncryption.DES;

public partial class ECB
{

    /// <summary>
    /// Initial Permutation
    /// </summary>
    private static readonly int[] iP =
        [
        58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7];

    private static readonly int[] endIP =
        [
        40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        ];

    private static readonly int[] expansion =
        [
        32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        ];

    private static readonly int[] pC1 =
        [
        57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        ];

    private static readonly int[] pC2 =
        [
        14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        ];

    private static readonly int[] lS =
        [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    private static readonly Transformation[] tS = Transformation.Initialization();

    public static void Test(byte[] bytes, byte[] _key)
    {
        int i, j;
        Console.Write("Unput: ");
        for (i = 0; i < bytes.Length; i++)
            Console.Write(bytes[7 - i].ToString("x2"));
        Console.WriteLine();

        ListBit[] bit = new ListBit[ListBit.Length];
        ListBit[] kys = new ListBit[ListBit.Length];

        for (i = 0, j = bytes.Length - 1; i < bytes.Length; i++, j--)
        {
            bit[i] = (ListBit)bytes[j];
            kys[i] = (ListBit)_key[j];
        }
        byte[] a = Encryption(bit, kys);

        Console.Write("Output Encryption: ");
        for (i = 0; i < a.Length; i++)
            Console.Write(a[i].ToString("x2"));
        Console.WriteLine();

        for (i = 0, j = bytes.Length - 1; i < bytes.Length; i++, j--)
        {
            bit[i] = (ListBit)a[7 - j];
            kys[i] = (ListBit)_key[j];
        }
        byte[] b = Decryption(bit, kys);

        Console.Write("Output Decryption: ");
        for (i = 0; i < a.Length; i++)
            Console.Write(b[i].ToString("x2"));
        Console.WriteLine();
    }

    public static void FileEncryption(string path, byte[] _key)
    {
        if (_key.Length > 8) throw new Exception("Key length greater than 8");
        else if (_key.Length < 8) throw new Exception("Key length less than 8");
        else if (Directory.Exists(path)) throw new Exception("File nop");

        string name = Path.GetFileName(path);

        using (FileStream fs = new FileStream($"{name}.key", FileMode.Create, FileAccess.Write))
            fs.Write(_key, 0, _key.Length);


        ListBit.ArrayBit[] arrKys = KeyGenerator(GetKey56(ListBit.Create(_key)));
        byte[]
            buffer1 = new byte[8],
            buffer2 = new byte[8];

        using (FileStream R = new FileStream(path, FileMode.Open, FileAccess.Read))
        using (FileStream W = new FileStream($"{name}.save", FileMode.Create, FileAccess.Write))
        {
            long Length = R.Length, i;
            W.Write(Encryption(ListBit.Create(BitConverter.GetBytes(Length)), arrKys), 0, 8);
            //W.Write(BitConverter.GetBytes(Length), 0, 8);
            for (i = 8; i <= Length; i += 8)
            {
                R.Read(buffer1, 0, 8);
                buffer2 = Encryption(ListBit.Create(buffer1), arrKys);
                W.Write(buffer2, 0, 8);
            }
            Length -= i - 8;
            if (Length > 0)
            {
                for (int j = 0; j < 8; j++)
                    buffer1[j] = 0;
                R.Read(buffer1, 0, (int)Length);
                buffer2 = Encryption(ListBit.Create(buffer1), arrKys);
                W.Write(buffer2, 0, 8);
            }
        }

    }
    public static void FileDecryption(string pathFile, string pathKey)
    {
        if (Directory.Exists(pathFile)) throw new Exception("File nop");
        else if (Directory.Exists(pathKey)) throw new Exception("Key nop");

        byte[] _key = new byte[8];
        using (FileStream fs = new FileStream(pathKey, FileMode.Open, FileAccess.Read))
        {
            if (fs.Length > 8) throw new Exception("Key length greater than 8");
            else if (fs.Length < 8) throw new Exception("Key length less than 8");
            fs.Read(_key, 0, _key.Length);
        }

        string name = Path.GetFileName(pathFile);
        string[] NS = name.Split('.');
        name = name.Remove(name.Length - NS[NS.Length - 1].Length - 1);
        //name = string.Concat(name, $".{NS[NS.Length - 1]}");

        ListBit.ArrayBit[] arrKys = KeyGenerator(GetKey56(ListBit.Create(_key)));
        byte[]
            buffer1 = new byte[8],
            buffer2 = new byte[8];

        using (FileStream R = new FileStream(pathFile, FileMode.Open, FileAccess.Read))
        using (FileStream W = new FileStream($"New_{name}", FileMode.Create, FileAccess.Write))
        {
            R.Read(buffer1, 0, 8);
            buffer1 = Decryption(ListBit.Create(buffer1), arrKys);
            long Length = BitConverter.ToInt64(buffer1), i;
            for (i = 8; i <= Length; i += 8)
            {
                R.Read(buffer1, 0, 8);
                buffer2 = Decryption(ListBit.Create(buffer1), arrKys);
                W.Write(buffer2, 0, 8);
            }
            Length = i - Length;
            if (Length > 0)
            {
                R.Read(buffer1, 0, 8);
                buffer2 = Decryption(ListBit.Create(buffer1), arrKys);
                W.Write(buffer2, 0, 8 - (int)Length);
            }
        }
    }
    public static ListBit[] GetKey56(ListBit[] bit)
    {
        ListBit.ArrayBit newBit = new ListBit.ArrayBit(ListBit.Create(7), 0, 56);
        ListBit.ArrayBit b = new ListBit.ArrayBit(bit, 0, 64);
        for (int i = 0; i < 56; i++)
            newBit[i] = b[pC1[i] - 1];
        return newBit.GetPseudoBits();
    }

    public static byte[] Encryption(ListBit[] bit, ListBit.ArrayBit[] arrKys)
    {
        bit = InitialPermutation(bit);
        ListBit.ArrayBit
            R = new ListBit.ArrayBit(bit, 32, 64),
            L = new ListBit.ArrayBit(bit, 0, 32),
            p;
        for (int i = 0, j; i < 16; i++)
        {
            p = L ^ Swap32(TransS(Expansion32To48(R) ^ arrKys[i + 1]));
            L = R;
            R = p;
        }
        ListBit[] end = End(L, R);

        byte[] bytes = new byte[end.Length];
        for (int i = 0; i < end.Length; i++)
            bytes[i] = (byte)end[i];
        return bytes;
    }
    public static byte[] Decryption(ListBit[] bit, ListBit.ArrayBit[] arrKys)
    {
        bit = InitialPermutation(bit);
        ListBit.ArrayBit
            R = new ListBit.ArrayBit(bit, 32, 64),
            L = new ListBit.ArrayBit(bit, 0, 32),
            p;
        for (int i = 0, j; i < 16; i++)
        {
            p = L ^ Swap32(TransS(Expansion32To48(R) ^ arrKys[16 - i]));
            L = R;
            R = p;
        }
        ListBit[] end = End(L, R);

        byte[] bytes = new byte[end.Length];
        for (int i = 0; i < end.Length; i++)
            bytes[i] = (byte)end[i];
        return bytes;
    }


    private static byte[] Encryption(ListBit[] bit, ListBit[] kys)
    {
        bit = InitialPermutation(bit);
        ListBit.ArrayBit
            R = new ListBit.ArrayBit(bit, 32, 64),
            L = new ListBit.ArrayBit(bit, 0, 32),
            p;
        ListBit.ArrayBit[] arrKys = KeyGenerator(GetKey56(kys));
        for (int i = 0, j; i < 16; i++)
        {
            p = L ^ Swap32(TransS(Expansion32To48(R) ^ arrKys[i + 1]));
            L = R;
            R = p;
        }
        ListBit[] end = End(L, R);

        byte[] bytes = new byte[end.Length];
        for (int i = 0; i < end.Length; i++)
            bytes[i] = (byte)end[i];
        return bytes;
    }

    private static byte[] Decryption(ListBit[] bit, ListBit[] kys)
    {
        bit = InitialPermutation(bit);
        ListBit.ArrayBit
            R = new ListBit.ArrayBit(bit, 32, 64),
            L = new ListBit.ArrayBit(bit, 0, 32),
            p;
        ListBit.ArrayBit[] arrKys = KeyGenerator(GetKey56(kys));
        for (int i = 0, j; i < 16; i++)
        {
            p = L ^ Swap32(TransS(Expansion32To48(R) ^ arrKys[16 - i]));
            L = R;
            R = p;
        }
        ListBit[] end = End(L, R);

        byte[] bytes = new byte[end.Length];
        for (int i = 0; i < end.Length; i++)
            bytes[i] = (byte)end[i];
        return bytes;
    }


    public static ListBit.ArrayBit[] KeyGenerator(ListBit[] bitKys56)
    {
        ListBit.ArrayBit[] arrayBits = new ListBit.ArrayBit[17];
        ListBit.ArrayBit
            RKys = new ListBit.ArrayBit(bitKys56, 28, 56),
            LKys = new ListBit.ArrayBit(bitKys56, 0, 28);
        for (int i = 0, j; true; i++)
        {
            arrayBits[i] = new ListBit.ArrayBit(Key56To48(bitKys56), 0, 48);
            if (i > 15) break;
            for (j = 0; j < lS[i]; j++)
            {
                RKys.Left();
                LKys.Left();
            }
        }
        return arrayBits;
    }

    private static ListBit[] InitialPermutation(ListBit[] bit)
    {
        ListBit[] newBit = ListBit.Create(bit.Length);
        int i = 0, SNPB, SNB, SPB, SB;
        for (; i < 64; i++)
        {
            SNPB = (int)Math.Truncate(i / (double)ListBit.Length);
            SNB = i % ListBit.Length;
            SPB = (int)Math.Truncate((iP[i] - 1) / (double)ListBit.Length);
            SB = (iP[i] - 1) % ListBit.Length;
            newBit[SNPB][SNB] = bit[SPB][SB];
        }
        return newBit;
    }

    private static ListBit[] Key56To48(ListBit[] bit)
    {
        int i, SNPB, SNB, SPB, SB;
        ListBit[] newBit = ListBit.Create(6);
        for (i = 0; i < 48; i++)
        {
            SNPB = (int)Math.Truncate(i / (double)ListBit.Length);
            SNB = i % ListBit.Length;
            SPB = (int)Math.Truncate((pC2[i] - 1) / (double)ListBit.Length);
            SB = (pC2[i] - 1) % ListBit.Length;
            newBit[SNPB][SNB] = bit[SPB][SB];
        }
        return newBit;
    }

    private static ListBit.ArrayBit Expansion32To48(ListBit.ArrayBit RBit)
    {
        ListBit.ArrayBit array = new ListBit.ArrayBit(ListBit.Create(6), 0, 48);
        for (int i = 0; i < 48; i++)
            array[i] = RBit[expansion[i] - 1];
        return array;
    }

    private static ListBit[] TransS(ListBit.ArrayBit bit)
    {
        int row, col;
        int[] column = new int[8];
        for (int i = 0, next = 0; i < 8; i++, next += 6)
        {
            row = bit.GetBit(next) << 1 | bit.GetBit(next + 5);
            col = bit.GetBit(next + 1) << 3 | bit.GetBit(next + 2) << 2 | bit.GetBit(next + 3) << 1 | bit.GetBit(next + 4);
            column[i] = tS[i].s[row, col];
        }

        ListBit[] bits = new ListBit[4];
        for (int i = 0, next = 0; i < 8; i += 2, next++)
            bits[next] = (ListBit)(byte)(column[i] << 4 | column[i + 1]);

        return bits;
    }

    private static ListBit.ArrayBit Swap32(ListBit[] bit)
    {
        ListBit.ArrayBit arrayBit = new ListBit.ArrayBit(bit, 0, 32);
        ListBit.ArrayBit arrayNewBit = new ListBit.ArrayBit(ListBit.Create(bit.Length), 0, 32);
        for (int i = 0; i < 32; i++)
            arrayNewBit[i] = arrayBit[Transformation.swap[i] - 1];
        return arrayNewBit;
    }

    private static ListBit[] End(ListBit.ArrayBit l, ListBit.ArrayBit r)
    {
        ListBit.ArrayBit arrayBit = new ListBit.ArrayBit(ListBit.Create(8), 0, 64);
        for (int i = 0; i < 32; i++)
        {
            arrayBit[i] = r[i];
            arrayBit[32 + i] = l[i];
        }
        ListBit.ArrayBit aNB = new ListBit.ArrayBit(ListBit.Create(8), 0, 64);
        for (int i = 0; i < 64; i++)
            aNB[i] = arrayBit[endIP[i] - 1];
        return aNB.GetPseudoBits();
    }
}
partial class ECB
{
    private class Transformation(int[,] _s)
    {

        public static readonly int[] swap =
            [
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
            ];

        public readonly int[,] s = _s;

        public static Transformation[] Initialization()
            =>
            [
                //S1
                new Transformation( new int[,]
                {
                    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
                }),
                //S2
                new Transformation(new int[,]
                    {
                    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
                    }),
                //S3
                new Transformation(new int[,]
                {
                    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
                }),
                //S4
                new Transformation(new int[,]
                    {
                    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
                    }),
                //S5
                new Transformation(new int[,]
                {
                    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
                }),
                //S6
                new Transformation(new int[,]
                {
                    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
                }),
                //S7
                new Transformation(new int[,]
                {
                    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
                }),
                //S8
                new Transformation(new int[,]
                {
                    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
                })
            ];

    }
}
