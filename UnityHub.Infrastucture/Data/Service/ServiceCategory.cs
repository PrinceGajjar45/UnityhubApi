using System.ComponentModel.DataAnnotations;

namespace UnityHub.Infrastructure.Data.Service
{
    public class ServiceCategory
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Name { get; set; } // e.g., "Mobile Repair", "Plumber", "Electrician"

        [Required]
        [MaxLength(500)]
        public string Description { get; set; }

        public string Icon { get; set; } // FontAwesome icon or image URL
        public int DisplayOrder { get; set; } = 0;
        public bool IsActive { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Navigation
        public virtual ICollection<ServiceProviderSkill> ServiceProviderSkills { get; set; } = new List<ServiceProviderSkill>();
    }
}