using System;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace ChilkatConsole
{
    internal class Program
    {
        static string APPLE_ROOT_CA_G3_FINGERPRINT = "63:34:3A:BF:B8:9A:6A:03:EB:B5:7E:9B:3F:5F:A7:BE:7C:4F:5C:75:6F:30:17:B3:A8:C4:88:C3:65:3E:91:79";

        static void Main(string[] args)
        {
            Chilkat.Rest rest = new Chilkat.Rest();
            Console.WriteLine(rest.Version);

            //JWSUsingHMACSHA256();
            //JWSGetProtectedHeader();
            X509OpenCertificate();
        }

        static void JWSUsingHMACSHA256()
        {
            // https://www.example-code.com/dotnet-core/jws_hmac_sha_256.asp
            // This requires the Chilkat API to have been previously unlocked.
            // See Global Unlock Sample for sample code.

            // Note: This example requires Chilkat v9.5.0.66 or greater.

            bool success;

            // First create the JWS Protected Header
            Chilkat.JsonObject jwsProtHdr = new Chilkat.JsonObject();
            jwsProtHdr.AppendString("typ", "JWT");
            jwsProtHdr.AppendString("alg", "HS256");
            Console.WriteLine("JWS Protected Header: " + jwsProtHdr.Emit());

            // Output:
            // JWS Protected Header: {"typ":"JWT","alg":"HS256"}

            Chilkat.Jws jws = new Chilkat.Jws();

            // Set the HMAC key:
            string hmacKey = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
            int signatureIndex = 0;
            jws.SetMacKey(signatureIndex, hmacKey, "base64url");

            // Set the protected header:
            jws.SetProtectedHeader(signatureIndex, jwsProtHdr);

            // Set the payload.
            bool bIncludeBom = false;
            string payloadStr = "In our village, folks say God crumbles up the old moon into stars.";
            jws.SetPayload(payloadStr, "utf-8", bIncludeBom);

            // Create the JWS
            // By default, the compact serialization is used.
            string jwsCompact = jws.CreateJws();
            if (jws.LastMethodSuccess != true)
            {
                Console.WriteLine(jws.LastErrorText);
                return;
            }

            Console.WriteLine("JWS: " + jwsCompact);

            // sample output:
            // JWS: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.SW4gb3VyIHZpbGxhZ2UsIGZvbGtzIHNheSBHb2QgY3J1bWJsZXMgdXAgdGhlIG9sZCBtb29uIGludG8gc3RhcnMu.bsYsi8HJ0N6OqGI1hKQ9QQRNPxxA5qMpcHLtOvXatk8

            // Now load the JWS, validate, and recover the original text.
            Chilkat.Jws jws2 = new Chilkat.Jws();

            // Load the JWS.
            success = jws2.LoadJws(jwsCompact);

            // Set the MAC key used for validation.
            signatureIndex = 0;
            jws2.SetMacKey(signatureIndex, hmacKey, "base64url");

            // Validate the 1st (and only) signature at index 0..
            int v = jws2.Validate(signatureIndex);
            if (v < 0)
            {
                // Perhaps Chilkat was not unlocked or the trial expired..
                Console.WriteLine("Method call failed for some other reason.");
                Console.WriteLine(jws2.LastErrorText);
                return;
            }

            if (v == 0)
            {
                Console.WriteLine("Invalid signature.  The MAC key was incorrect, the JWS was invalid, or both.");
                return;
            }

            // If we get here, the signature was validated..
            Console.WriteLine("Signature validated.");

            // Recover the original content:
            Console.WriteLine(jws2.GetPayload("utf-8"));

            // Examine the protected header:
            Chilkat.JsonObject joseHeader = jws2.GetProtectedHeader(signatureIndex);
            if (jws2.LastMethodSuccess != true)
            {
                Console.WriteLine("No protected header found at the given index.");
                return;
            }

            joseHeader.EmitCompact = false;

            Console.WriteLine("Protected (JOSE) header:");
            Console.WriteLine(joseHeader.Emit());
        }

        static void JWSGetProtectedHeader()
        {

            string jwsCompact = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.SW4gb3VyIHZpbGxhZ2UsIGZvbGtzIHNheSBHb2QgY3J1bWJsZXMgdXAgdGhlIG9sZCBtb29uIGludG8gc3RhcnMu.bsYsi8HJ0N6OqGI1hKQ9QQRNPxxA5qMpcHLtOvXatk8";
            Chilkat.Jws jws2 = new Chilkat.Jws();

            // Load the JWS.
            bool success = jws2.LoadJws(jwsCompact);
            int signatureIndex = 0;

            Chilkat.JsonObject joseHeader = jws2.GetProtectedHeader(signatureIndex);
            if (jws2.LastMethodSuccess != true)
            {
                Console.WriteLine("No protected header found at the given index.");
                return;
            }

            joseHeader.EmitCompact = false;

            Console.WriteLine("Protected (JOSE) header:");
            Console.WriteLine(joseHeader.Emit());

        }

        static void X509OpenCertificate()
        {

            // The path to the certificate.
            var dir = Environment.CurrentDirectory;
            string Certificate = $"{dir}\\AppleIncRootCertificate.cer";

            // Load the certificate into an X509Certificate object.
            X509Certificate cert = new X509Certificate(Certificate);

            // Get the value.
            string resultsTrue = cert.ToString(true);

            // Display the value to the console.
            Console.WriteLine(resultsTrue);

            // Get the value.
            string resultsFalse = cert.ToString(false);

            // Display the value to the console.
            Console.WriteLine(resultsFalse);

        }
    }
}
