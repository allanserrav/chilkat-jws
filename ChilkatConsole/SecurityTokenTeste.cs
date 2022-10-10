using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ChilkatConsole
{

    internal static class SecurityTokenTeste
    {
        public static Dictionary<string, string> GetClaimsByToken(string jwtToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.ReadJwtToken(jwtToken.Replace("/g", ""));
            token.Header.TryGetValue("x5c", out object x5c);
            var certeficatesItems = JsonConvert.DeserializeObject<IEnumerable<string>>(x5c.ToString());

            ValidateJWS(tokenHandler, jwtToken, certeficatesItems.First());

            return token.Claims.ToDictionary(c => c.Type, v => v.Value);
        }

        private static void ValidateJWS(JwtSecurityTokenHandler tokenHandler, string jwtToken, string publicKey)
        {
            var certificateBytes = Base64UrlEncoder.DecodeBytes(publicKey);
            var certificate = new X509Certificate2(certificateBytes);
            var eCDsa = certificate.GetECDsaPublicKey();

            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new ECDsaSecurityKey(eCDsa),
            };

            tokenHandler.ValidateToken(jwtToken, tokenValidationParameters, out var securityToken);
        }

        public static string GetProtectedHeader(string jwsCompact)
        {
            Chilkat.Jws jws = new Chilkat.Jws();

            // Load the JWS.
            bool success = jws.LoadJws(jwsCompact);
            int signatureIndex = 0;

            Chilkat.JsonObject joseHeader = jws.GetProtectedHeader(signatureIndex);
            if (jws.LastMethodSuccess != true)
            {
                Console.WriteLine("No protected header found at the given index.");
                return String.Empty;
            }

            string payload = jws.GetPayload("utf-8");

            //joseHeader.EmitCompact = false;

            Console.WriteLine("Protected (JOSE) header:");
            return joseHeader.Emit();

        }

        //static void JWSUsingHMACSHA256()
        //{
        //    // https://www.example-code.com/dotnet-core/jws_hmac_sha_256.asp
        //    // This requires the Chilkat API to have been previously unlocked.
        //    // See Global Unlock Sample for sample code.

        //    // Note: This example requires Chilkat v9.5.0.66 or greater.

        //    bool success;

        //    // First create the JWS Protected Header
        //    Chilkat.JsonObject jwsProtHdr = new Chilkat.JsonObject();
        //    jwsProtHdr.AppendString("typ", "JWT");
        //    jwsProtHdr.AppendString("alg", "HS256");
        //    Console.WriteLine("JWS Protected Header: " + jwsProtHdr.Emit());

        //    // Output:
        //    // JWS Protected Header: {"typ":"JWT","alg":"HS256"}

        //    Chilkat.Jws jws = new Chilkat.Jws();

        //    // Set the HMAC key:
        //    string hmacKey = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
        //    int signatureIndex = 0;
        //    jws.SetMacKey(signatureIndex, hmacKey, "base64url");

        //    // Set the protected header:
        //    jws.SetProtectedHeader(signatureIndex, jwsProtHdr);

        //    // Set the payload.
        //    bool bIncludeBom = false;
        //    string payloadStr = "In our village, folks say God crumbles up the old moon into stars.";
        //    jws.SetPayload(payloadStr, "utf-8", bIncludeBom);

        //    // Create the JWS
        //    // By default, the compact serialization is used.
        //    string jwsCompact = jws.CreateJws();
        //    if (jws.LastMethodSuccess != true)
        //    {
        //        Console.WriteLine(jws.LastErrorText);
        //        return;
        //    }

        //    Console.WriteLine("JWS: " + jwsCompact);

        //    // sample output:
        //    // JWS: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.SW4gb3VyIHZpbGxhZ2UsIGZvbGtzIHNheSBHb2QgY3J1bWJsZXMgdXAgdGhlIG9sZCBtb29uIGludG8gc3RhcnMu.bsYsi8HJ0N6OqGI1hKQ9QQRNPxxA5qMpcHLtOvXatk8

        //    // Now load the JWS, validate, and recover the original text.
        //    Chilkat.Jws jws2 = new Chilkat.Jws();

        //    // Load the JWS.
        //    success = jws2.LoadJws(jwsCompact);

        //    // Set the MAC key used for validation.
        //    signatureIndex = 0;
        //    jws2.SetMacKey(signatureIndex, hmacKey, "base64url");

        //    // Validate the 1st (and only) signature at index 0..
        //    int v = jws2.Validate(signatureIndex);
        //    if (v < 0)
        //    {
        //        // Perhaps Chilkat was not unlocked or the trial expired..
        //        Console.WriteLine("Method call failed for some other reason.");
        //        Console.WriteLine(jws2.LastErrorText);
        //        return;
        //    }

        //    if (v == 0)
        //    {
        //        Console.WriteLine("Invalid signature.  The MAC key was incorrect, the JWS was invalid, or both.");
        //        return;
        //    }

        //    // If we get here, the signature was validated..
        //    Console.WriteLine("Signature validated.");

        //    // Recover the original content:
        //    Console.WriteLine(jws2.GetPayload("utf-8"));

        //    // Examine the protected header:
        //    Chilkat.JsonObject joseHeader = jws2.GetProtectedHeader(signatureIndex);
        //    if (jws2.LastMethodSuccess != true)
        //    {
        //        Console.WriteLine("No protected header found at the given index.");
        //        return;
        //    }

        //    joseHeader.EmitCompact = false;

        //    Console.WriteLine("Protected (JOSE) header:");
        //    Console.WriteLine(joseHeader.Emit());
        //}



        //static void JWTToken()
        //{
        //    var stream = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.SW4gb3VyIHZpbGxhZ2UsIGZvbGtzIHNheSBHb2QgY3J1bWJsZXMgdXAgdGhlIG9sZCBtb29uIGludG8gc3RhcnMu.bsYsi8HJ0N6OqGI1hKQ9QQRNPxxA5qMpcHLtOvXatk8";
        //    var handler = new JwtSecurityTokenHandler();
        //    var jsonToken = handler.ReadToken(stream);
        //    var tokenS = jsonToken as JwtSecurityToken;
        //}
    }
}
