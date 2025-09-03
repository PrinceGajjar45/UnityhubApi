using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace UnityHub.Infrastructure.Data.Service
{
    public class ServiceProvider
    {
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; }

        [ForeignKey("UserId")]
        public virtual ApplicationUser User { get; set; }

        // Business Information
        [Required]
        [MaxLength(200)]
        public string BusinessName { get; set; }

        [Required]
        [MaxLength(1000)]
        public string BusinessDescription { get; set; }

        // Business Location (separate from user's personal location)
        [Required]
        public string BusinessAddress { get; set; }

        [Required]
        public string BusinessCity { get; set; }

        [Required]
        public string BusinessState { get; set; }

        [Required]
        public string BusinessCountry { get; set; }

        [Required]
        public string BusinessZipCode { get; set; }

        [Required]
        [MaxLength(256)]
        public string BusinessEmail { get; set; }

        [Required]
        public string BusinessPhone { get; set; }

        public decimal BusinessLatitude { get; set; }
        public decimal BusinessLongitude { get; set; }
        public bool IsVerified { get; set; } = false;
        public decimal Rating { get; set; } = 0;
        public int CompletedJobs { get; set; } = 0;
        public int TotalReviews { get; set; } = 0;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        public virtual ICollection<ServiceProviderSkill> Skills { get; set; } = new List<ServiceProviderSkill>();

        // Helper Methods
        public void UpdateFromUserProfile()
        {
            if (User != null)
            {
                BusinessPhone = User.PhoneNumber;
                // Only update business location if not already set
                if (string.IsNullOrEmpty(BusinessAddress))
                {
                    BusinessAddress = User.Address;
                    BusinessCity = User.City;
                    BusinessState = User.State;
                    BusinessCountry = User.Country;
                    BusinessZipCode = User.ZipCode;
                    BusinessLatitude = User.Latitude ?? 0;
                    BusinessLongitude = User.Longitude ?? 0;
                }
            }
        }
    }
}