using System.ComponentModel.DataAnnotations;

namespace UnityHub.API.Authentication
{
    public class UpdateUserProfile
    {
        public string? FirstName { get; set; } = string.Empty;
        public string? LastName { get; set; } = string.Empty;
        public string? PhoneNumber { get; set; } = string.Empty;
        public string? Location { get; set; } = string.Empty;
        public string? ProfileUrl { get; set; } = string.Empty;
        public string? UserName { get; set; } = string.Empty;

        [Required]
        public string Email { get; set; }
    }
}
