namespace DESEncryption.DES;

public class SM
{


    public static void FileEncryption(string path, byte[] _key, int seed = 777)
    {
        if (_key.Length > 8) throw new Exception("Key length greater than 8");
        else if (_key.Length < 8) throw new Exception("Key length less than 8");
        else if (Directory.Exists(path)) throw new Exception("File nop");


        ListBit.ArrayBit[] arrKys = ECB.KeyGenerator(ECB.GetKey56(ListBit.Create(_key)));

        string name = Path.GetFileName(path);

        using (FileStream fs = new FileStream($"{name}.key", FileMode.Create, FileAccess.Write))
            fs.Write(_key, 0, _key.Length);

        byte[]
            buffer1 = new byte[8],
            buffer2 = new byte[8];

        using (FileStream R = new FileStream(path, FileMode.Open, FileAccess.Read))
        using (FileStream W = new FileStream($"{name}.save", FileMode.Create, FileAccess.Write))
            FStream(R, W, arrKys, seed);

    }


    public static void FileDecryption(string pathFile, string pathKey, int seed = 777)
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


        using (FileStream R = new FileStream(pathFile, FileMode.Open, FileAccess.Read))
        using (FileStream W = new FileStream($"New_{name}", FileMode.Create, FileAccess.Write))
            FStream(R, W, ECB.KeyGenerator(ECB.GetKey56(ListBit.Create(_key))), seed);
    }

    private static void FStream(FileStream R, FileStream W, ListBit.ArrayBit[] arrKys, int seed)
    {
        long Length = R.Length, i;
        byte[]
            buffer1 = new byte[8],
            buffer2 = new byte[8];
        GammaGenerator GG = new GammaGenerator(seed);

        for (i = 8; i <= Length; i += 8)
        {
            R.Read(buffer1, 0, 8);
            buffer2 = ECB.Encryption(ListBit.Create(BitConverter.GetBytes(GG.NextLong())), arrKys);
            XOR8(buffer1, buffer2);
            W.Write(buffer1, 0, 8);
        }
        Length = i - Length;
        if (Length > 0)
        {
            R.Read(buffer1, 0, 8);
            buffer2 = ECB.Encryption(ListBit.Create(BitConverter.GetBytes(GG.NextLong())), arrKys);
            XOR8(buffer1, buffer2);
            W.Write(buffer1, 0, 8 - (int)Length);
        }
    }

    private static void XOR8(byte[] mainB, byte[] secondaryB)
    {
        for (int i = 0; i < 8; i++)
            mainB[i] ^= secondaryB[i];
    }



}
