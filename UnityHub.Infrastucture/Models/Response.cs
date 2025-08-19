namespace UnityHub.Infrastructure.Models
{
    public class Response
    {
        public string Status { get; set; }
        public string Message { get; set; }
        public string? Token { get; set; }
        public DateTime? Expiration { get; set; }
    }
}
