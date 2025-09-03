using Microsoft.AspNetCore.Identity;

namespace UnityHub.Infrastructure.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string? UserRole { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public bool IsServiceProvider { get; set; }
        public string? ProfileUrl { get; set; }
        public string? PhoneNumber { get; set; }
        public string? State { get; set; }
        public string? Country { get; set; }
        public string? ZipCode { get; set; }
        public decimal? Latitude { get; set; }
        public decimal? Longitude { get; set; }
        public string? TwoFactorCode { get; set; }
        public DateTime? TwoFactorCodeExpiration { get; set; }
        public string? Address { get; set; }
        public string? City { get; set; }
    }
}