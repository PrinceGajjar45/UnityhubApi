using Microsoft.AspNetCore.Identity;

namespace UnityHub.Infrastructure.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool IsServiceProvider { get; set; } = false;
        public string Location { get; set; }
        public string ProfileUrl { get; set; }
        public string PhoneNumber { get; set; }
        public string? TwoFactorCode { get; set; }
        public DateTime? TwoFactorCodeExpiration { get; set; }
    }
}
