using System.Security.Cryptography.X509Certificates;
using x509Cert.Models;

namespace x509Cert.Services
{
    public interface ICertificateService
    {
        IEnumerable<(string, string, long)> OpenCertificate(CertificateDto certificateDto, bool hasChain, X509KeyStorageFlags x509KeyStorageFlags);
    }
}