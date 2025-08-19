using Microsoft.AspNetCore.Identity;

namespace UnityHub.Infrastructure.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string? TwoFactorCode { get; set; }
        public DateTime? TwoFactorCodeExpiration { get; set; }
    }
}
