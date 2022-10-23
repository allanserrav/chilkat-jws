using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ChilkatConsole
{

    public class X509CertificateTeste
    {
        const string APPLE_ROOT_CA_G3_FINGERPRINT = "63:34:3A:BF:B8:9A:6A:03:EB:B5:7E:9B:3F:5F:A7:BE:7C:4F:5C:75:6F:30:17:B3:A8:C4:88:C3:65:3E:91:79";
        public X509CertificateTeste()
        {
        }

        public static void ValidateAppleProtectedHeader(AppleProtectedHeader header)
        {
            var x509certs = header.X5C.Select(x => new X509Certificate2(Encoding.Default.GetBytes(x))).ToList();

            bool dateValid = x509certs.All(x => x.NotBefore < DateTime.Now && DateTime.Now < x.NotAfter);
            if (!dateValid)
            {
                throw new Exception("Data Inválida");
            }

            // Check that each certificate, except for the last, is issued by the subsequent one.
            if (x509certs.Count >= 2)
            {
                for (int i = 0; i < x509certs.Count - 1; i++)
                {
                    var subject = x509certs[i];
                    var issuer = x509certs[i + 1];

                    bool validateIssuer = subject.IssuerName.Equals(issuer.FriendlyName);
                    bool validatePublicKey = subject.PublicKey.Equals(issuer.PublicKey);
                    if (!validateIssuer || !validatePublicKey)
                    {
                        throw new Exception("Issuer inválido");
                    }
                }
            }

            // Ensure that the last certificate in the chain is the expected Apple root CA.
            if (x509certs[^1].Thumbprint != APPLE_ROOT_CA_G3_FINGERPRINT)
            {
                throw new Exception("Apple root CA inválido");
            }
        }

        public static void ValidateAppleProtectedHeader2(AppleProtectedHeader header)
        {
            var x509certs = header.X5C.Select(x => new X509Certificate2(Encoding.Default.GetBytes(x))).ToList();
            var file = new FileInfo(@"C:\Users\vasco\Downloads\AppleRootCA-G3.cer");
            var authority = GetCertificateByFile(file);

            // Check that each certificate
            foreach(var x509cert in x509certs)
            {
                if (!TryGetBuildChain(x509certs.Last(), authority, out var chain1))
                {
                    throw new Exception("Certificado inválido");
                }
            }

            // Ensure that the last certificate in the chain is the expected Apple root CA.
            if (TryGetBuildChain(x509certs.Last(), authority, out var chain))
            {
                var valid = chain.ChainElements
                .Cast<X509ChainElement>()
                .Any(x => x.Certificate.Thumbprint == authority.Thumbprint);

                if (!valid)
                    throw new Exception("Apple root CA inválido");
            }
        }

        public static bool TryGetBuildChain(X509Certificate2 client, X509Certificate2 authority, out X509Chain chain)
        {
            chain = new X509Chain();

            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            chain.ChainPolicy.ExtraStore.Add(authority);

            // Do the preliminary validation.
            return chain.Build(client);
        }

        public static bool ChainVerifyWithPolicy(string x5c)
        {
            // Load the certificate into an X509Certificate object.
            var certificate = new X509Certificate2(Encoding.Default.GetBytes(x5c));
            using X509Chain ch = new X509Chain(true);
            ch.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            ch.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            bool r = ch.Build(certificate);
            return r;
        }

        public static X509Certificate2 GetCertificateByFile(FileInfo file)
        {
            // Load the certificate into an X509Certificate object.
            return new X509Certificate2(file.FullName);
        }

        public static void DisplayStoreCertificates()
        {
            //Create new X509 store from local certificate store.
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

            //Output store information.
            Console.WriteLine("Store Information");
            Console.WriteLine("Number of certificates in the store: {0}", store.Certificates.Count);
            Console.WriteLine("Store location: {0}", store.Location);
            Console.WriteLine("Store name: {0} {1}", store.Name, Environment.NewLine);

            //Put certificates from the store into a collection so user can select one.
            X509Certificate2Collection fcollection = store.Certificates;
            X509Certificate2Collection collection = X509Certificate2UI.SelectFromCollection(fcollection, "Select an X509 Certificate", "Choose a certificate to examine.", X509SelectionFlag.SingleSelection);
            X509Certificate2 certificate = collection[0];
            X509Certificate2UI.DisplayCertificate(certificate);

            //Output chain information of the selected certificate.
            X509Chain ch = new X509Chain();
            ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            ch.Build(certificate);
            Console.WriteLine("Chain Information");
            Console.WriteLine("Chain revocation flag: {0}", ch.ChainPolicy.RevocationFlag);
            Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
            Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
            Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
            Console.WriteLine("Chain status length: {0}", ch.ChainStatus.Length);
            Console.WriteLine("Chain application policy count: {0}", ch.ChainPolicy.ApplicationPolicy.Count);
            Console.WriteLine("Chain certificate policy count: {0} {1}", ch.ChainPolicy.CertificatePolicy.Count, Environment.NewLine);

            //Output chain element information.
            Console.WriteLine("Chain Element Information");
            Console.WriteLine("Number of chain elements: {0}", ch.ChainElements.Count);
            Console.WriteLine("Chain elements synchronized? {0} {1}", ch.ChainElements.IsSynchronized, Environment.NewLine);

            foreach (X509ChainElement element in ch.ChainElements)
            {
                Console.WriteLine("Element issuer name: {0}", element.Certificate.Issuer);
                Console.WriteLine("Element certificate valid until: {0}", element.Certificate.NotAfter);
                Console.WriteLine("Element certificate is valid: {0}", element.Certificate.Verify());
                Console.WriteLine("Element error status length: {0}", element.ChainElementStatus.Length);
                Console.WriteLine("Element information: {0}", element.Information);
                Console.WriteLine("Number of element extensions: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);

                if (ch.ChainStatus.Length > 1)
                {
                    for (int index = 0; index < element.ChainElementStatus.Length; index++)
                    {
                        Console.WriteLine(element.ChainElementStatus[index].Status);
                        Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
                    }
                }
            }
            store.Close();
        }
    }
}
