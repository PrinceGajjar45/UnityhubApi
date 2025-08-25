using System.ComponentModel.DataAnnotations;

namespace UnityHub.Infrastructure.Models
{
    public class ReSentVerificationCode
    {
        [Required]
        public string Email { get; set; }
    }
}
