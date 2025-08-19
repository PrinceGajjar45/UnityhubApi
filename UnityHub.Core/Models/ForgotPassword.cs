using System.ComponentModel.DataAnnotations;

namespace UnityHub.Core.Models
{
    public class ForgotPassword
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
