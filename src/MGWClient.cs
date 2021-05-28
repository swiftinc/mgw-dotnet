using System;
using System.Net.Http;
using System.Threading.Tasks;
using JWT;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace MGWClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            /* Retrieve the following variables from MGW configurations. */
            var busAppName = "BO";
            var profileId = "trackerProfile";
            var sharedKey = "Abcd1234Abcd1234Abcd1234Abcd1234";

            /* Host & port number where the MGW instance is running. */
            var baseaddress = "https://localhost:9003";

            /* Path for gpi Tracker - 'Get Changed Payment Transactions' API.
               Sample API call using MGW configured for the SWIFT API Sandbox. */
            var url = "swift/mgw/swift-apitracker/v4/payments/changed/transactions";

            using (var httpClientHandler = new HttpClientHandler())
            {
                /* Turning off certificate checks in the demo app to test with SWIFT API Sandbox.
                    This is not recommeded for Live implementation. */
                httpClientHandler.ServerCertificateCustomValidationCallback = 
                                        (message, cert, chain, errors) => { return true; };
                using (var client = new HttpClient(httpClientHandler))
                {
                    try {
                        /* Create signed JWT token to authenticate with MGW. */
                        var token = 
                            createToken(busAppName, profileId, baseaddress + "/" + url, sharedKey);

                        client.BaseAddress = new Uri(baseaddress);

                        /* Set the token in the authorization header. */
                        client.DefaultRequestHeaders.Add("Authorization", "Bearer " + token);
                        client.DefaultRequestHeaders.Add("X-SWIFT-Signature", "false");

                        HttpResponseMessage response = await client.GetAsync(url);
                        response.EnsureSuccessStatusCode();

                        var resp = await response.Content.ReadAsStringAsync();

                        string authvalue = 
                                response.Headers.GetValues("Authorization").FirstOrDefault();

                        Console.WriteLine("Response - " + "\n" + resp + "\n");
                        Console.WriteLine("Response Token - " + "\n" + authvalue + "\n");

                        if (verifyResponse(resp, authvalue, sharedKey)) {
                            Console.WriteLine("Response verification suceeded.");
                        } else {
                            Console.WriteLine("Response verification failed.");
                        }
                    } catch (Exception ex) {
                        Console.WriteLine(ex.Message);
                        Console.WriteLine(ex.StackTrace);
                    }                
                }
            }
        }
        
        static string createToken(string appname, string profileid, 
                                    string path, string sharedkey) {
            
            /* Generate a random string for JWT Identifier for every API request. */
            string jtistr = getUniqueString(25);
            Console.WriteLine("Random JWT Identifier - " + jtistr + "\n"); 

            /* Get current time in milliseconds. */
            long timenow = DateTimeOffset.Now.ToUnixTimeMilliseconds(); 
            /* Get current time plus 30 minutes in milliseconds. */ 
            long timefuture = timenow + 1800000; 

            /* Create JWT data payload */
            var pload = new Dictionary<string, object>()
            {
                { "jti", jtistr },
                { "iss", appname },
                {"profileId", profileid},
                {"iat", timenow},
                {"exp", timefuture},
                {"absPath", path}
            };
            
            /* Create JWT in the form of "header.payload.signature" */
            var token = Jwt.JsonWebToken.Encode(pload, sharedkey, Jwt.JwtHashAlgorithm.HS256);
            Console.WriteLine("Token - " + token + "\n");
                                
            return token;
        }

        static bool verifyResponse(string response, string authvalue, string sharedkey) {
            bool retval = true;
            string jsonstr = null;
            string token = authvalue.Substring("Bearer ".Length);

            /* Verify JWT signature. */
            try {
                jsonstr = Jwt.JsonWebToken.Decode(token, sharedkey);
                Console.WriteLine("Signature verification succeeded.");
                Console.WriteLine("\n" + "Claims - " + jsonstr + "\n"); 
            } catch (Jwt.SignatureVerificationException ex) {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);

                return false;
            } 
            
            /* Uncomment to compare digest. */
            
            /*
            Dictionary<string, object> dict = 
                    System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(jsonstr);
            string digest = (string) (dict["digest"]).ToString();
            
            Console.WriteLine("Received Digest - " + digest + "\n");

            string respdigest = ComputeHashSha256(System.Text.Encoding.UTF8.GetBytes(response));
            
            retval = (string.Compare(digest, respdigest)  == 0) ? true : false;
            */

            return retval;
        }
        
        static string ComputeHashSha256(byte[] data) {
            var sha256 = SHA256.Create();
            
            return Base64UrlEncoder.Encode(sha256.ComputeHash(data).ToString());
        }

        static string getUniqueString(int len) {
                using(var rng = new RNGCryptoServiceProvider()) {
                var bit_count = (len * 6);
                var byte_count = ((bit_count + 7) / 8);
                var bytes = new byte[byte_count];
                rng.GetBytes(bytes);
                
                return Convert.ToBase64String(bytes);
            }
        }
    }
}
