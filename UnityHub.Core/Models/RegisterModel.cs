using System.ComponentModel.DataAnnotations;

namespace UnityHub.Core.Models
{
    public class RegisterModel
    {
        public string Username { get; set; }

        [Required(ErrorMessage = "User FirstName is required")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "User LastName is required")]
        public string LastName { get; set; }

        public bool IsServiceProvider { get; set; } = false;

        public string Location { get; set; }

        public string ProfileUrl { get; set; }

        public string PhoneNumber { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        [Required]
        public string ConfirmPassword { get; set; }

    }
}
