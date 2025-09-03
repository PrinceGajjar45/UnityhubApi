namespace UnityHub.Core.Models
{
    public class AdminDto
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Department { get; set; }
        public bool IsSuperAdmin { get; set; }
        public bool CanManageCategories { get; set; }
        public bool CanManageProviders { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}