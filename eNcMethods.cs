using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Data;
using System.Windows.Forms;
using System.IO;
using System.Threading;

namespace eNcryptorByAlexanderN
{
    class eNcMethods
    {
        CancellationTokenSource CancelAnyTask = new CancellationTokenSource();
        public class XOR
        {
            private static string GetRepeatKey(string s, int n)
            {
                var r = s;
                while (r.Length < n)
                {
                    r += r;
                }

                return r.Substring(0, n);
            }

            private static string Cipher(string text, string secretKey, CancellationToken Cancel)
            {
                var currentKey = GetRepeatKey(secretKey, text.Length);
                var res = string.Empty;
                for (var i = 0; i < text.Length; i++)
                {
                    if (Cancel.IsCancellationRequested)
                        break;
                    res += ((char)(text[i] ^ currentKey[i])).ToString();
                }

                return res;
            }

            public static string Encrypt(string plainText, string password, CancellationToken Cancel)
            {
                return Base64.ToBase64N(Encoding.UTF8.GetBytes(Cipher(plainText, password, Cancel)));
            }

            public static string Decrypt(string encryptedText, string password, CancellationToken Cancel)
            {
                encryptedText = Encoding.UTF8.GetString(Base64.FromBase64N(encryptedText));
                return Cipher(encryptedText, password, Cancel);
            }
        }
        public class Vigenere
        {
            static char[] characters = new char[] { 'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж', 'З', 'И',
                                                  'Й', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Р', 'С',
                                                  'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ь', 'Ы', 'Ъ',
                                                  'Э', 'Ю', 'Я', ' ', '1', '2', '3', '4', '5', '6', '7',
                                                  '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '@', '$', '%', '^', '&', '*', '(', ')', '_', '-', '=', '+', ',', '?',
         'а','б','в','г','д','е','ё','ж','з','и','й','к','л','м','н','о','п','р','с','т','у','ф','х','ц','ч','ш','щ','ъ','ы','ь','э','ю','я','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','/','[',']',':'};

            static int N = characters.Length;

            public static string Decrypt(string input, string keyword, CancellationToken Cancel)
            {
                input = Encoding.UTF8.GetString(Base64.FromBase64N(input));
                string result = "";

                int keyword_index = 0;

                foreach (char symbol in input)
                {
                    if (Cancel.IsCancellationRequested)
                        break;
                    int p = (Array.IndexOf(characters, symbol) + N -
                        Array.IndexOf(characters, keyword[keyword_index])) % N;

                    result += characters[p];

                    keyword_index++;

                    if ((keyword_index + 1) == keyword.Length)
                        keyword_index = 0;
                }
                return result;
            }

            public static string Encrypt(string input, string keyword, CancellationToken Cancel)
            {
                string result = "";

                int keyword_index = 0;

                foreach (char symbol in input)
                {
                    if (Cancel.IsCancellationRequested)
                        break;
                    int c = (Array.IndexOf(characters, symbol) +
                        Array.IndexOf(characters, keyword[keyword_index])) % N;

                    result += characters[c];

                    keyword_index++;

                    if ((keyword_index + 1) == keyword.Length)
                        keyword_index = 0;
                }
                return (Base64.ToBase64N(Encoding.UTF8.GetBytes(result)));
            }
        }

        public static class Scytale
        {
            public static string Encrypt(string text, int d, CancellationToken Cancel)
            {
                var k = text.Length % d;
                if (k > 0)
                {
                    text += new string('=', d - k);
                }

                var column = text.Length / d;
                var result = "";

                for (int i = 0; i < column; i++)
                {
                    for (int j = 0; j < d; j++)
                    {
                        if (Cancel.IsCancellationRequested)
                            break;
                        result += text[i + column * j].ToString();
                    }
                }

                return (Base64.ToBase64N(Encoding.UTF8.GetBytes(result)));
            }

            public static string Decrypt(string text, int d, CancellationToken Cancel)
            {
                text = Encoding.UTF8.GetString(Base64.FromBase64N(text));
                var column = text.Length / d;
                var symbols = new char[text.Length];
                int index = 0;
                for (int i = 0; i < column; i++)
                {
                    for (int j = 0; j < d; j++)
                    {
                        if (Cancel.IsCancellationRequested)
                            break;
                        symbols[i + column * j] = text[index];
                        index++;
                    }
                }

                return string.Join("", symbols);
            }
        }

        public class RSA
        {
            static char[] characters = new char[] { 'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж', 'З', 'И',
                                                  'Й', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Р', 'С',
                                                  'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ь', 'Ы', 'Ъ',
                                                  'Э', 'Ю', 'Я', ' ', '1', '2', '3', '4', '5', '6', '7',
                                                  '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '@', '$', '%', '^', '&', '*', '(', ')', '_', '-', '=', '+', ',', '?',
         'а','б','в','г','д','е','ё','ж','з','и','й','к','л','м','н','о','п','р','с','т','у','ф','х','ц','ч','ш','щ','ъ','ы','ь','э','ю','я','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','/','[',']',':'};

            public class GenerateKeyPair
            {
                public static long Calculate_d(long m)
                {
                    long d = m - 1;

                    for (long i = 2; i <= m; i++)
                        if ((m % i == 0) && (d % i == 0))
                        {
                            d--;
                            i = 1;
                        }

                    return d;
                }

                public static void GetDN(long p, long q, out long d, out long n)
                {
                    n = p * q;
                    long m = (p - 1) * (q - 1);
                    d = Calculate_d(m);
                }

                public static long Calculate_e(long d, long m)
                {
                    long e = 10;

                    while (true)
                    {
                        if ((e * d) % m == 1)
                            break;
                        else
                            e++;
                    }

                    return e;
                }

            }

            public static string Encrypt(long p, long q, string s, long d, long n, CancellationToken Cancel)
            {
                if (IsTheNumberSimple(p) && IsTheNumberSimple(q))
                {
                    n = p * q;
                    long m = (p - 1) * (q - 1);
                    d = GenerateKeyPair.Calculate_d(m);
                    long e_ = GenerateKeyPair.Calculate_e(d, m);

                    List<string> result = RSA_Encode(s, e_, n, Cancel);


                    string ret = "";
                    foreach (string item in result)
                    { ret += item + "/S/"; }
                    return ret;
                }
                else
                    throw new Exception("Внутренняя ошибка!");

            }

            public static string Decrypt(long d, long n, string text, CancellationToken Cancel)
            {
                String[] input = text.Split(new string[] { "/S/" }, StringSplitOptions.RemoveEmptyEntries);

                string result = RSA_Decode(input, d, n, Cancel);

                return result;
            }

            public static bool IsTheNumberSimple(long n)
            {
                if (n < 2)
                    return false;

                if (n == 2)
                    return true;

                for (long i = 2; i < n; i++)
                    if (n % i == 0)
                        return false;

                return true;
            }

            private static List<string> RSA_Encode(string s, long e, long n, CancellationToken Cancel)
            {
                List<string> result = new List<string>();

                BigInteger bi;

                for (int i = 0; i < s.Length; i++)
                {
                    if (Cancel.IsCancellationRequested)
                        break;
                    int index = Array.IndexOf(characters, s[i]);

                    bi = new BigInteger(index);
                    bi = BigInteger.Pow(bi, (int)e);

                    BigInteger n_ = new BigInteger((int)n);

                    bi = bi % n_;

                    result.Add(bi.ToString());
                }

                return result;
            }


            private static string RSA_Decode(string[] input, long d, long n, CancellationToken Cancel)
            {
                string result = "";

                BigInteger bi;

                foreach (string item in input)
                {
                    if (Cancel.IsCancellationRequested)
                        break;
                    bi = new BigInteger(Convert.ToDouble(item));
                    bi = BigInteger.Pow(bi, (int)d);

                    BigInteger n_ = new BigInteger((int)n);

                    bi = bi % n_;

                    int index = Convert.ToInt32(bi.ToString());

                    result += characters[index].ToString();
                }

                return result;
            }
        }

        public class Base64
        {
            static readonly char[] base64Table = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O',
                                                       'P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d',
                                                       'e','f','g','h','i','j','k','l','m','n','o','p','q','r','s',
                                                       't','u','v','w','x','y','z','0','1','2','3','4','5','6','7',
                                                       '8','9','+','/','=' };

            public static string ToBase64N(byte[] data)
            {
                var arrayOfBinaryStrings = data.Select(x => Convert.ToString(x, 2).PadLeft(8, '0'));
                var count = arrayOfBinaryStrings.Count();
                var append = count % 3 == 1 ? "==" : count % 3 == 2 ? "=" : "";

                var allBytes = string.Join("", arrayOfBinaryStrings);
                var countOfBytes = allBytes.Count();
                var remOfDivision = countOfBytes % 6;
                var newList = Enumerable.Range(0, countOfBytes / 6).Select(x => allBytes.Substring(x * 6, 6)).ToList();

                if (remOfDivision != 0)
                {
                    newList.Add(allBytes.Substring(countOfBytes / 6 * 6, remOfDivision).PadRight(6, '0'));
                }

                return (string.Join("", newList.Select(x => base64Table[Convert.ToByte(x, 2)])) + append);
            }

            static Dictionary<char, int> base64DIctionary = new Dictionary<char, int>()
{
    {'A', 0 },{'B', 1 },{'C', 2 },{'D', 3 },{'E', 4 },{'F', 5 },{'G', 6 },{'H', 7 },{'I', 8 },{'J', 9 },{'K', 10 },{'L', 11 },{'M', 12 },{'N', 13 },{'O', 14 },{'P', 15 },{'Q', 16 },{'R', 17 },{'S', 18 },{'T', 19 },{'U', 20 },{'V', 21 },{'W', 22 },{'X', 23 },{'Y', 24 },{'Z', 25 },{'a', 26 },{'b', 27 },{'c', 28 },{'d', 29 },{'e', 30 },{'f', 31 },{'g', 32 },{'h', 33 },{'i', 34 },{'j', 35 },{'k', 36 },{'l', 37 },{'m', 38 },{'n', 39 },{'o', 40 },{'p', 41 },{'q', 42 },{'r', 43 },{'s', 44 },{'t', 45 },{'u', 46 },{'v', 47 },{'w', 48 },{'x', 49 },{'y', 50 },{'z', 51 },{'0', 52 },{'1', 53 },{'2', 54 },{'3', 55 },{'4', 56 },{'5', 57 },{'6', 58 },{'7', 59 },{'8', 60 },{'9', 61 },{'+', 62 },{'/', 63 },{'=', -1 }
};

            public static byte[] FromBase64N(string str)
            {
                var allBytes = string.Join("", str.Where(x => x != '=').Select(x => Convert.ToString(base64DIctionary[x], 2).PadLeft(6, '0')));

                var countOfBytes = allBytes.Count();

                return Enumerable.Range(0, countOfBytes / 8).Select(x => allBytes.Substring(x * 8, 8)).Select(x => Convert.ToByte(x, 2)).ToArray();

            }

        }

        public static long PrimeFinder(long n)
        {
            while (true)
            {
                if (eNcMethods.RSA.IsTheNumberSimple(n) == true)
                {
                    return n;
                }
                n++;
            }
        }

        public static string GenerateRandomString()
        {
            string s0 = "";
            string s1 = "";
            Random rnd = new Random();
            int n;
            string st = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (int j = 0; j < 10; j++)
            {
                n = rnd.Next(0, 61);
                s1 = st.Substring(n, 1);
                s0 += s1;
            }
            return s0;
        }

        public static int GenerateRandomEasyString(int lenght)
        {
            int s0 = 1;
            Random rnd = new Random();
            s0 = rnd.Next(1, lenght);
            return s0;
        }

    }
}
