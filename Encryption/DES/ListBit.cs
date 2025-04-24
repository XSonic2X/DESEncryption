namespace DESEncryption.DES;

public partial struct ListBit
{
    public ListBit()
    { }

    private ListBit(byte v)
    {
        for (int i = 0; i < 8; i++)
            values[i] = bit[v, i];
    }

    public const int Length = 8;

    private static readonly bool[,] bit = Initialization();

    public readonly bool[] values = new bool[Length];

    public bool this[int i]
    {
        get => values[i];
        set => values[i] = value;
    }

    public override string ToString()
    {
        string txt = "[";
        for (int i = 0; i < values.Length; i++)
        {
            if ((i % 5) == 4)
                txt += "] [";
            txt += Convert.ToInt16(values[i]);
        }
        return txt + "]";
    }

    public static explicit operator ListBit(byte v)
        => new ListBit(v);

    public static explicit operator byte(ListBit bit)
    {
        int v = 0;
        for (int i = 0; i < bit.values.Length; i++)
            if (bit.values[i]) v |= 1 << (7 - i);
        return (byte)v;
    }

    public static ListBit[] Create(int l)
    {
        ListBit[] pseudoBits = new ListBit[l];
        for (int i = 0; i < l; i++)
            pseudoBits[i] = new ListBit();
        return pseudoBits;
    }

    public static ListBit[] Create(byte[] bytes)
    {
        ListBit[] pseudoBits = new ListBit[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
            pseudoBits[i] = (ListBit)bytes[i];
        return pseudoBits;
    }

    private static bool[,] Initialization()
    {
        bool[,] b = new bool[256, Length];
        bool[] bytes = new bool[Length];
        bool add = false;
        for (int i = 1; i < 256; i++)
        {
            add = true;
            for (int j = 0; j < bytes.Length; j++)
            {
                if (bytes[j])
                {
                    bytes[j] = false;
                    add = true;
                }
                else if (add)
                {
                    bytes[j] = true;
                    add = false;
                    break;
                }
            }
            for (int j = 0; j < bytes.Length; j++)
                b[i, j] = bytes[(bytes.Length - j - 1)];
        }
        return b;
    }

}
partial struct ListBit
{
    public struct ArrayBit
    {

        public ArrayBit(ListBit[] bit, int begin, int end)
        {
            length = end - begin;
            _begin = begin;
            _bit = bit;
        }

        public int length;

        private int _begin;

        private readonly ListBit[] _bit;

        public bool this[int index]
        {
            get
            {
                if (index >= length) throw new Exception("index >= length");
                index += _begin;
                int SPB = (int)Math.Truncate(index / (double)Length);
                int SB = index % Length;
                return _bit[SPB][SB];
            }
            set
            {
                if (index >= length) throw new Exception("index >= length");
                index += _begin;
                int SPB = (int)Math.Truncate(index / (double)Length);
                int SB = index % Length;
                _bit[SPB][SB] = value;
            }
        }

        public ListBit[] GetPseudoBits()
            => _bit;

        public int GetBit(int index)
            => this[index] ? 1 : 0;

        public void Left()
        {
            bool a = this[0];
            for (int i = 1; i < length; i++)
                this[i - 1] = this[i];
            this[length - 1] = a;
        }

        public void Right()
        {
            bool a = this[length - 1];
            for (int i = length - 2; i >= length; i++)
                this[i + 1] = this[i];
            this[0] = a;
        }

        public string Info()
        {
            string txt = "";
            for (int i = 0; i < length; i++)
            {
                if ((i + 1) % 4 == 1)
                    txt += " ";
                txt += this[i] ? 1 : 0;
            }
            return txt;
        }

        public static ArrayBit operator ^(ArrayBit a, ArrayBit b)
        {
            int i, length = Math.Min(a.length, b.length);
            ArrayBit array = new ArrayBit(Create(length / 8), 0, length);
            for (i = 0; i < length; i++)
                array[i] = a[i] ^ b[i];
            return array;
        }

    }

}
