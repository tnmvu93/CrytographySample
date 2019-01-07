using Rsa;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Rsa_2
{
    class Program
    {
        static void Main(string[] args)
        {
            var txtCert = string.Empty;
            var txtKey = string.Empty;
            using (TextReader tr = new StreamReader("private.key"))
            {
                txtKey = tr.ReadToEnd();
            }
            using (TextReader tr = new StreamReader("public.cer"))
            {
                txtCert = tr.ReadToEnd();
            }
            Certificate cert = new Certificate(txtCert, txtKey, string.Empty);
            var xcert = cert.GetCertificateFromPEMstring(false);

            RSACryptoServiceProvider publicKeyProvider = (RSACryptoServiceProvider)xcert.PublicKey.Key;
            var encrypter = new RSACryptoServiceProvider();
            encrypter.ImportParameters(publicKeyProvider.ExportParameters(false));

            RSACryptoServiceProvider privateKeyProvider = (RSACryptoServiceProvider)xcert.PrivateKey;
            var decrypter = new RSACryptoServiceProvider();
            decrypter.ImportParameters(privateKeyProvider.ExportParameters(true));

            var plainText = "hello world";
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            var encryptedText = encrypter.Encrypt(ByteConverter.GetBytes(plainText), false);

            var decryptedText = decrypter.Decrypt(encryptedText, false);

            Console.WriteLine(decryptedText);
            Console.ReadKey();
        }
    }
}
