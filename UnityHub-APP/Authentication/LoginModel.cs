using System.ComponentModel.DataAnnotations;

namespace UnityHub.API.Authentication
{
    public class LoginModel
    {
        [Required]
        public string PhoneNumber { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
