using System.Text.Json.Serialization;

namespace UnityHub.Core.Models
{
    public class PostalPinCodeResponse
    {
        [JsonPropertyName("Message")]
        public string Message { get; set; } = string.Empty;

        [JsonPropertyName("Status")]
        public string Status { get; set; } = string.Empty;

        [JsonPropertyName("PostOffice")]
        public List<PostOffice>? PostOffice { get; set; }
    }

    public class PostOffice
    {
        [JsonPropertyName("Name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("Description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("BranchType")]
        public string BranchType { get; set; } = string.Empty;

        [JsonPropertyName("DeliveryStatus")]
        public string DeliveryStatus { get; set; } = string.Empty;

        [JsonPropertyName("Circle")]
        public string Circle { get; set; } = string.Empty;

        [JsonPropertyName("District")]
        public string District { get; set; } = string.Empty;

        [JsonPropertyName("Division")]
        public string Division { get; set; } = string.Empty;

        [JsonPropertyName("Region")]
        public string Region { get; set; } = string.Empty;

        [JsonPropertyName("State")]
        public string State { get; set; } = string.Empty;

        [JsonPropertyName("Country")]
        public string Country { get; set; } = string.Empty;
    }
}