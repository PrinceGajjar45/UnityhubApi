using System.ComponentModel.DataAnnotations;

namespace UnityHub.API.Authentication
{
    public class ReSentVerificationCode
    {
        [Required]
        public string Email { get; set; }
    }
}
