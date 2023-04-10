namespace x509Cert.Models
{
    public class CertificateDto
    {
        public string CertificateName { get; set; }

        public string CertificatePassword { get; set; }

        public byte[] CertificateContent { get; set; }
    }
}