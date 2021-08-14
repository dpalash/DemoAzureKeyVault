using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Blob;

namespace DemoAzureKeyVault
{
    public class KeyVaultIdentifierHelper
    {
        private const string KeyFormat = "{0}/keys/{1}";
        private const string SecretFormat = "{0}/secrets/{1}";
        private readonly string keyVaultUrl;

        public KeyVaultIdentifierHelper(string keyVaultUrl)
        {
            this.keyVaultUrl = keyVaultUrl;
        }

        public string GetKeyIdentifier(string keyName)
        {
            return string.Format(KeyFormat, this.keyVaultUrl, keyName);
        }

        public string GetSecretIdentifier(string secretName)
        {
            return string.Format(SecretFormat, this.keyVaultUrl, secretName);
        }
    }

    class Program
    {
        private const string ApplicationId = "4c2b641c-a21c-4e95-a0ba-b149c1ddb5fa";

        private const string ApplicationSecret = "3GgpmCTSTJNXBYYIfKsPcU9yT3D3RUIx78s8XrwggNk=";

        private const string TextToEncrypt = "Text to encrypt";

        static void Main(string[] args)
        {
            Task t = MainAsync(args);
            t.Wait();
        }

        static async Task MainAsync(string[] args)
        {
            //var keyClient = new KeyVaultClient(async (authority, resource, scope) =>
            //{
            //    var adCredential = new ClientCredential(ApplicationId, ApplicationSecret);
            //    var authenticationContext = new AuthenticationContext(authority, null);
            //    return (await authenticationContext.AcquireTokenAsync(resource, adCredential)).AccessToken;
            //});

            //// Get the key details
            //var keyIdentifier = "https://sfneptuneserverkeyvault.vault.azure.net:443/keys/SFNeptuneServerFirstKey";
            //var key = await keyClient.GetKeyAsync(keyIdentifier);
            //var publicKey = Convert.ToBase64String(key.Key.N);

            //using (var rsa = new RSACryptoServiceProvider())
            //{
            //    var p = new RSAParameters() { Modulus = key.Key.N, Exponent = key.Key.E };
            //    rsa.ImportParameters(p);
            //    var byteData = Encoding.Unicode.GetBytes(TextToEncrypt);

            //    // Encrypt and Decrypt
            //    var encryptedText = rsa.Encrypt(byteData, true);
            //    var decryptedData = await keyClient.DecryptAsync(keyIdentifier, "RSA-OAEP", encryptedText);
            //    var decryptedText = Encoding.Unicode.GetString(decryptedData.Result);

            //    // Sign and Verify
            //    var hasher = new SHA256CryptoServiceProvider();
            //    var digest = hasher.ComputeHash(byteData);
            //    var signature = await keyClient.SignAsync(keyIdentifier, "RS256", digest);
            //    var isVerified = rsa.VerifyHash(digest, "Sha256", signature.Result);
            //}










            // This is standard code to interact with Blob storage.
            StorageCredentials creds = new StorageCredentials("vismadata", "nI1HaCOKasv1O9xr4uNIjw1bmemUOfU6wkGC50GIxh+wsxKsLEYYDz1kE9Z3F3pPn6+YUwHycHo6nf6KLp56Uw==");
            CloudStorageAccount account = new CloudStorageAccount(creds, useHttps: true);
            CloudBlobClient client = account.CreateCloudBlobClient();
            CloudBlobContainer contain = client.GetContainerReference("vismadatacontainer");
            contain.CreateIfNotExists();

            // The Resolver object is used to interact with Key Vault for Azure Storage.
            // This is where the GetToken method from above is used.
            KeyVaultKeyResolver cloudResolver = new KeyVaultKeyResolver(GetToken);

            // Retrieve the key that you created previously.
            // The IKey that is returned here is an RsaKey.
            // Remember that we used the names contosokeyvault and testrsakey1.
            var rsa = cloudResolver.ResolveKeyAsync("https://sfneptuneserverkeyvault.vault.azure.net:443/keys/SFNeptuneServerFirstKey", CancellationToken.None).GetAwaiter().GetResult();


            // Now you simply use the RSA key to encrypt by setting it in the BlobEncryptionPolicy.
            BlobEncryptionPolicy policy = new BlobEncryptionPolicy(rsa, null);
            BlobRequestOptions options = new BlobRequestOptions() { EncryptionPolicy = policy };

            // Reference a block blob.
            CloudBlockBlob blob = contain.GetBlockBlobReference("entmba-dummy.txt");

            // Upload using the UploadFromStream method.
            using (var stream = System.IO.File.OpenRead(@"C:\data\entmba-dummy.txt"))
                blob.UploadFromStream(stream, stream.Length, null, options, null);



        }

        private async static Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(ApplicationId, ApplicationSecret);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }
    }
}
