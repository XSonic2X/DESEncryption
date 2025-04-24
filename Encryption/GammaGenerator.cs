namespace DESEncryption;

public class GammaGenerator
{
    public GammaGenerator(int seed = 777)
    {
        _seed = seed;
        A = Next();
    }
    private int _seed;
    private int i = 1;
    private int j = 1;
    private long A;
    private const long q = 0x1f31d;

    public uint Next()
    {
        long a = (_seed | j) / q;
        long b = (_seed | j) % q;
        a = ((0x41a7 + i) * b) - ((0xb14 + i) * a);
        long c = (a % 0x1000) * (64 + (j * 0xf));
        if (A == c)
        {
            j += 3;
            if (j > 1000) j -= 1000;
            a = _seed / q;
            b = _seed % q;
            a = ((0x41a7 + i) * b) - ((0xb14 + i) * a);
            c = (a % 0x1000) * (64 + (j * 0xf));
            A = c;
        }
        i++;
        return (uint)c;
    }
    public long NextLong()
        => Next() | (long)Next() << (8 * 3) | (long)Next() << (8 * 6);

    public void Reset()
    {
        i = j = 1;
        A = Next();
    }

}
