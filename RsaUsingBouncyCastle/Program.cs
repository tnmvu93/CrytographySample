using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RsaUsingBouncyCastle
{
    class Program
    {
        static void Main(string[] args)
        {
            var encrypter = ReadEncryptedPrivateKey();
            var decrypter = ReadPublicKey();

            var plainText = "Hello world";
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            var encryptedText = encrypter.ProcessBlock(ByteConverter.GetBytes(plainText), 0, ByteConverter.GetBytes(plainText).Length);

            var decryptedText = decrypter.ProcessBlock(encryptedText, 0, encryptedText.Length);

            Console.WriteLine(ByteConverter.GetString(decryptedText));
            Console.ReadKey();
        }

        static RsaEngine ReadPrivateKey()
        {
            using (var reader = File.OpenText("private.key"))
            {
                var pem = new PemReader(reader);
                var o = (AsymmetricCipherKeyPair)pem.ReadObject();
                RsaEngine e = new RsaEngine();
                e.Init(true, o.Private);
                return e;
            }
        }

        static RsaEngine ReadEncryptedPrivateKey()
        {
            using (var reader = File.OpenText("encrypted-private.key"))
            {
                var pf = new PasswordFinder("fxd");
                var pem = new PemReader(reader, pf);
                var o = (AsymmetricCipherKeyPair)pem.ReadObject();
                RsaEngine e = new RsaEngine();
                e.Init(true, o.Private);
                return e;
            }
        }

        static RsaEngine ReadPublicKey()
        {
            using (var reader = File.OpenText("public.key"))
            {
                var pem = new PemReader(reader);
                var o = (AsymmetricKeyParameter)pem.ReadObject();
                RsaEngine e = new RsaEngine();
                e.Init(false, o);
                return e;
            }
        }
    }
}
