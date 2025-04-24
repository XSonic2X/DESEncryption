using DESEncryption.DES;
using System.Text;

namespace Encryption
{
    internal class Program
    {
        static void Main(string[] args)
        {
            switch (args.Length)
            {
                case 1:
                    SelectEncryption(args[0]);
                    break;
                case 2:
                    SelectDecryption(args);
                    break;
                default:
                    break;
            }
            Console.WriteLine("End");
            Console.ReadLine();
        }

        static void SelectEncryption(string path)
        {
            ConsoleColor color = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("The maximum key size is 8 bytes!");
            Console.ForegroundColor = color;
            Console.Write("GetKys:");
            byte[] bK = GetKys();
            Console.WriteLine();
            Console.WriteLine("Encryption stage");
            SM.FileEncryption(path, bK);
        }

        static void SelectDecryption(string[] args)
        {
            string file = string.Empty, fileKey = string.Empty;
            string[] txt;
            for (int i = 0; i < args.Length; i++)
            {
                txt = args[i].Split('.');
                switch (txt[txt.Length - 1].ToLower())
                {
                    case "save":
                        file = args[i];
                        break;
                    case "key":
                        fileKey = args[i];
                        break;
                    default:
                        Console.WriteLine($"Incorrect format: {args[i]}");
                        return;
                }
            }
            Console.WriteLine("Decryption stage");
            SM.FileDecryption(file, fileKey);
        }

        static byte[] GetKys()
        {
            string input = "";

            while (true)
            {
                ConsoleKeyInfo keyInfo = Console.ReadKey(true);
                switch (keyInfo.Key)
                {
                    case ConsoleKey.Enter:
                    case ConsoleKey.Escape:
                        byte[] bs = Encoding.UTF8.GetBytes(input);
                        byte[] nbs = new byte[8];
                        Array.Copy(bs, nbs, bs.Length);
                        return nbs;
                    default:
                        if (Encoding.UTF8.GetByteCount(input) >= 8)
                            return Encoding.UTF8.GetBytes(input);
                        input += keyInfo.KeyChar;
                        Console.Write(keyInfo.KeyChar);
                        break;
                }

            }


        }

    }
}
