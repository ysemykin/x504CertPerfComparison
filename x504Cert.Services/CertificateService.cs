using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using x509Cert.Models;
using static System.Net.Mime.MediaTypeNames;

namespace x509Cert.Services
{
    public class CertificateService : ICertificateService
    {
        private static byte[] ReadStream(Stream stream)
        {
            using MemoryStream memoryStream = new();
            stream.CopyTo(memoryStream);
            return memoryStream.ToArray();
        }

        public IEnumerable<(string, string, long)> OpenCertificate(CertificateDto certificateDto, bool hasChain, X509KeyStorageFlags x509KeyStorageFlags)
        {
            var result = new List<(string, string, long)>();

            X509Certificate2? rootCertificate = null;
            X509Certificate2? subCACertificate = null;

            try
            {
                using X509Chain chain = new();
                if (hasChain)
                {
                    var appPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                    rootCertificate = new X509Certificate2(appPath+"\\Certs\\RootCert.der");
                    subCACertificate = new X509Certificate2(appPath+"\\Certs\\SubCACert.der");

                    //var assembly = Assembly.GetExecutingAssembly();

                    //using (var stream = assembly.GetManifestResourceStream("x509Cert.Services.Certs.RootPilot.der"))
                    //{
                    //    if (stream == null)
                    //    {
                    //        result.Add(new("inf", "Root pilot certificate not found.", 0));
                    //    }
                    //    else
                    //    {
                    //        rootCertificate = new X509Certificate2(ReadStream(stream));
                    //    }
                    //}

                    //using (var stream = assembly.GetManifestResourceStream("x509Cert.Services.Certs.SubCAValidPilot.der"))
                    //{
                    //    if (stream == null)
                    //    {
                    //        result.Add(new("inf", "SubCA valid pilot certificate not found.", 0));
                    //    }
                    //    else
                    //    {
                    //        subCACertificate = new X509Certificate2(ReadStream(stream));
                    //    }
                    //}

                    chain.Reset();
                    chain.ChainPolicy.CustomTrustStore.Clear();

                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreRootRevocationUnknown;

                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

                    if (rootCertificate != null)
                    {
                        chain.ChainPolicy.CustomTrustStore.Add(rootCertificate);
                    }
                    if (subCACertificate != null)
                    {
                        chain.ChainPolicy.CustomTrustStore.Add(subCACertificate);
                    }

                }
                var timer = Stopwatch.StartNew();

                using X509Certificate2 certificate = new(certificateDto.CertificateContent, certificateDto.CertificatePassword, x509KeyStorageFlags);

                if (hasChain)
                {
                    var chainValidity = chain.Build(certificate);
                    if (!chainValidity)
                    {
                        result.Add(new("inf", "The certificate chain validation has failed.", 0));
                    }
                }

                timer.Stop();
                result.Add(new("data", "OpenCertificate", timer.ElapsedMilliseconds));
                timer.Restart();

                var publicKey = certificate.GetPublicKeyString();
                if (string.IsNullOrEmpty(publicKey))
                {
                    result.Add(new("inf", "The certificate doesn't have a public key.", 0));
                }

                timer.Stop();
                result.Add(new("data", "GetPublicKey", timer.ElapsedMilliseconds));
                timer.Restart();

                if (certificate.HasPrivateKey)
                {
                    using (RSA? rsaPrivateKey = certificate.GetRSAPrivateKey())
                    {
                        if (rsaPrivateKey == null)
                        {
                            result.Add(new("inf", "Failed to extract private key.", 0));
                        }
                    }

                    timer.Stop();
                    result.Add(new("data", "GetRSAPrivateKey", timer.ElapsedMilliseconds));
                    timer.Restart();

                    var signingPayload = GetByteArray(2048);

                    var signature = CreateSignature(signingPayload, certificate);

                    timer.Stop();
                    result.Add(new("data", "CreateSignature", timer.ElapsedMilliseconds));
                    timer.Restart();

                    var verificationResult = VerifySignature(signingPayload, certificate, signature);
                    if (!verificationResult)
                    {
                        result.Add(new("inf", "The signature was invalid", 0));
                    }
                    timer.Stop();
                    result.Add(new("data", "VerifySignature", timer.ElapsedMilliseconds));

                }
                else
                {
                    result.Add(new("inf", "The certificate doesn't have a private key.", 0));
                }

            }
            catch (Exception ex)
            {
                result.Add(new("inf", ex.Message, 0));
            }
            finally 
            {
                rootCertificate?.Dispose();
                subCACertificate?.Dispose();
            }
            return result;
        }

        public byte[] CreateSignature(byte[] dataToSign, X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("Provided certificate object can't be null.");
            }

            using (RSA? rsa = certificate.GetRSAPrivateKey())
            {
                if (rsa == null)
                {
                    throw new ArgumentException("Provided certificate doesn't have a private key.");
                }
                return rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            }
        }
        public bool VerifySignature(byte[] dataToVerify, X509Certificate2 certificate, byte[] signature)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("Provided certificate object can't be null.");
            }

            using (RSA? rsa = certificate.GetRSAPublicKey())
            {
                if (rsa == null)
                {
                    throw new ArgumentException("Provided certificate doesn't have a public key.");
                }

                return rsa.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            }
        }

        private byte[] GetByteArray(int sizeInBytes)
        {
            Random rnd = new Random();
            byte[] b = new byte[sizeInBytes];
            rnd.NextBytes(b);
            return b;
        }
    }
}