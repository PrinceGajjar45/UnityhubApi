using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace UnityHub.Infrastructure.Data.Service
{
    public class ServiceProviderSkill
    {
        public int Id { get; set; }

        // Foreign Keys
        [Required]
        public int ServiceProviderId { get; set; }

        [Required]
        public int ServiceCategoryId { get; set; }

        // Skill Details
        public int YearsOfExperience { get; set; } = 0;

        [MaxLength(200)]
        public string Certification { get; set; }

        [Column(TypeName = "decimal(10,2)")]
        public decimal HourlyRate { get; set; } = 0;

        public bool IsPrimarySkill { get; set; } = false;
        public bool IsAvailable { get; set; } = true;

        // Timestamps
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Navigation Properties
        [ForeignKey("ServiceProviderId")]
        public virtual ServiceProvider ServiceProvider { get; set; }

        [ForeignKey("ServiceCategoryId")]
        public virtual ServiceCategory ServiceCategory { get; set; }
    }
}