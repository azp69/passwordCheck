using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

// Ohjelma lähettää https://haveibeenpwned.com/ palvelimelle sha1-hashatun salasanan 5 ensimmäistä merkkiä.
// Vastauksena tulee lista sha1-hashatuista salasanoista, jotka alkaa näillä merkeillä.
// Koko salasanaa ei siis lähetetä missään vaiheessa eteenpäin, vaan lopullinen tsekkaus tapahtuu tässä ohjelmassa
// vertaamalla omaa salasanaa takaisin saatuun listaan.

// https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange <- tuolta lisää infoa miten homma toimii!

namespace passCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Password you want to check:");
            string pass = Console.ReadLine();

            checkPass(Hash(pass));

            Console.ReadLine();
        }

        static string Hash(string input)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                { 
                    sb.Append(b.ToString("X2"));
                }

                return sb.ToString();
            }
        }


        static async void checkPass(string passHash)
        {
            string url = "https://api.pwnedpasswords.com/range/" + passHash.Substring(0,5);
            string strippedHash = passHash.Substring(5);
            
            using (HttpClient client = new HttpClient())
            {
                try
                {
                    client.DefaultRequestHeaders.Add("User-Agent", "c# password checker");
                    HttpResponseMessage response = await client.GetAsync(url);
                    Console.WriteLine("Checking...");
                    response.EnsureSuccessStatusCode();
                    string responseBody = await response.Content.ReadAsStringAsync();

                    if (responseBody.Contains(strippedHash))
                    {
                        int startpos = responseBody.IndexOf(strippedHash) + 36;
                        int endpos = responseBody.IndexOf(Environment.NewLine, startpos);

                        Console.WriteLine("Your password was found " + responseBody.Substring(startpos, endpos - startpos) + " times!");
                    }
                    else
                    {
                        Console.WriteLine("Congratz! Nothing found... yet!");
                    }
                }
                catch (HttpRequestException e)
                {
                    Console.WriteLine("\nException Caught!");
                    Console.WriteLine("Message :{0} ", e.Message);
                }
            }
        }
    }
}
