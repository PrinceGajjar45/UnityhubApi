namespace UnityHub.Core.Models
{
    public class ServiceProviderSkillDto
    {
        public int Id { get; set; }
        public int ServiceProviderId { get; set; }
        public int ServiceCategoryId { get; set; }
        public int YearsOfExperience { get; set; }
        public string Certification { get; set; }
        public decimal HourlyRate { get; set; }
        public bool IsPrimarySkill { get; set; }
        public bool IsAvailable { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}