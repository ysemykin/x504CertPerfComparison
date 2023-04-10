using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using x509Cert.Services;
using x509Cert.Models;
using System.Text;

namespace x509Cert.PerfComparison.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class CertificateController : ControllerBase
    {

        private readonly ILogger<CertificateController> _logger;
        private readonly ICertificateService _certificateService;

        public CertificateController(ICertificateService certificateService, ILogger<CertificateController> logger)
        {
            _certificateService = certificateService;
            _logger = logger;
        }

        [HttpGet("test")]
        public ActionResult<string> GetTestString()
        {
            _logger.LogInformation("WebAPI:GetTestString was called.");
            return Ok("Some test string.");
        }

        [HttpPost("open-cert")]
        public ActionResult<string> OpenCertificate([FromBody][Required()] CertificateDto certificateDto)
        {
            _logger.LogInformation("WebAPI:OpenCertificate was called.");
            var result = new List<(string, string, long)>();

            try
            {
                // warm-up call
                _certificateService.OpenCertificate(certificateDto, true, X509KeyStorageFlags.DefaultKeySet);

                result.Add(new("title", "EphemeralKeySet", 0));
                var result1 = _certificateService.OpenCertificate(certificateDto, false, X509KeyStorageFlags.EphemeralKeySet);

                result.AddRange(result1);

                result.Add(new("title", "Exportable", 0));
                var result2 = _certificateService.OpenCertificate(certificateDto, false, X509KeyStorageFlags.Exportable);
                result.AddRange(result2);

                result.Add(new("title", "DefaultKeySet", 0));
                var result3 = _certificateService.OpenCertificate(certificateDto, false, X509KeyStorageFlags.DefaultKeySet);
                result.AddRange(result3);

                result.Add(new("title", "Chaining EphemeralKeySet", 0));
                var result21 = _certificateService.OpenCertificate(certificateDto, true, X509KeyStorageFlags.EphemeralKeySet);
                result.AddRange(result21);

                result.Add(new("title", "Chaining Exportable", 0));
                var result22 = _certificateService.OpenCertificate(certificateDto, true, X509KeyStorageFlags.Exportable);
                result.AddRange(result22);

                result.Add(new("title", "Chaining DefaultKeySet", 0));
                var result23 = _certificateService.OpenCertificate(certificateDto, true, X509KeyStorageFlags.DefaultKeySet);
                result.AddRange(result23);

            }
            catch (Exception ex)
            {
                result.Add(new("inf", ex.Message, 0));
            }
            return Ok(GetResultText(result));
        }

        private IEnumerable<string> GetResult(IEnumerable<(string, string, long)> values)
        {
            var resultList = new List<string>
            {
                GetLineString(),
                string.Format("|{0,5} {1,30} |{2,10} |", "", "Operation", "ms"),
            };

            foreach (var value in values) 
            { 
                switch (value.Item1) 
                {
                    case "title":
                        resultList.Add(GetLineString());
                        resultList.Add(string.Format("|{0,5} {1,30}  {2,10} |", "", value.Item2, ""));
                        resultList.Add(GetLineString());
                        break;
                    case "inf":
                        resultList.Add(string.Format("|{0,48} |", value.Item2));
                        break;
                    case "data":
                        resultList.Add(string.Format("|{0,5}|{1,30} |{2,10} |", "", value.Item2, value.Item3));
                        break;
                    default: break;
                }

            }

            resultList.Add(GetLineString());

            return resultList;
        }

        private string GetResultText(IEnumerable<(string, string, long)> values)
        {
            var sb = new StringBuilder();

            sb.AppendLine(GetLineString());
            sb.AppendLine(string.Format("|{0,5} {1,30} |{2,10} |", "", "Operation", "ms"));

            foreach (var value in values)
            {
                switch (value.Item1)
                {
                    case "title":
                        sb.AppendLine(GetLineString());
                        sb.AppendLine   (string.Format("|{0,5} {1,30}  {2,10} |", "", value.Item2, ""));
                        sb.AppendLine(GetLineString());
                        break;
                    case "inf":
                        sb.AppendLine(string.Format("|{0,48} |", value.Item2));
                        break;
                    case "data":
                        sb.AppendLine(string.Format("|{0,5}|{1,30} |{2,10} |", "", value.Item2, value.Item3));
                        break;
                    default: break;
                }

            }

            sb.AppendLine(GetLineString());

            return sb.ToString();
        }


        private string GetLineString()
        {
            return "".PadLeft(50, '-');
        }

    }
}
