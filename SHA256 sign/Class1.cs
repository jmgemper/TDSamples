using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SHA
{
    public class Class1
    {
        public bool SignSHA256(string pfxCert, string SignString, ref string hashOfString, ref string signature)
        {
            var hash = new System.Text.StringBuilder();
            Byte[] certificate = File.ReadAllBytes(pfxCert);
            X509Certificate2 cert2 = new X509Certificate2(certificate, "12345", X509KeyStorageFlags.Exportable);
            SHA256Managed shHash = new SHA256Managed();
            byte[] computedHash = shHash.ComputeHash(Encoding.UTF8.GetBytes(SignString));
            foreach (byte theByte in computedHash)
                hash.Append(theByte.ToString("x2"));
            hashOfString = hash.ToString();

            var certifiedRSACryptoServiceProvider = cert2.PrivateKey as RSACryptoServiceProvider;
            RSACryptoServiceProvider defaultRSACryptoServiceProvider = new RSACryptoServiceProvider();
            defaultRSACryptoServiceProvider.ImportParameters(certifiedRSACryptoServiceProvider.ExportParameters(true));
            byte[] signedHashValue = defaultRSACryptoServiceProvider.SignData(computedHash, "SHA256");
            signature = Convert.ToBase64String(signedHashValue);
          

            RSACryptoServiceProvider publicCertifiedRSACryptoServiceProvider = cert2.PublicKey.Key as RSACryptoServiceProvider;
            bool verify = publicCertifiedRSACryptoServiceProvider.VerifyData(computedHash, "SHA256", signedHashValue);
            return verify;
        }
    }
}
