namespace UnityHub.Core.Models
{
    public class ServiceProviderDto
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string BusinessName { get; set; }
        public string BusinessDescription { get; set; }
        public string BusinessAddress { get; set; }
        public string BusinessCity { get; set; }
        public string BusinessState { get; set; }
        public string BusinessCountry { get; set; }
        public string BusinessZipCode { get; set; }
        public decimal BusinessLatitude { get; set; }
        public decimal BusinessLongitude { get; set; }
        public string BusinessPhone { get; set; }
        public string BusinessEmail { get; set; }
        public bool IsVerified { get; set; }
        public decimal Rating { get; set; }
        public int TotalReviews { get; set; }
        public int CompletedJobs { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}