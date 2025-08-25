using System.ComponentModel.DataAnnotations;

namespace UnityHub.Core.Models
{
    public class ReSentVerificationCode
    {
        [Required]
        public string Email { get; set; }
    }
}
