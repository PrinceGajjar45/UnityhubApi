using System.Text.Json.Serialization;

namespace UnityHub.Core.CommonModel
{
    public class Response
    {
        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty;

        [JsonPropertyName("message")]
        public string Message { get; set; } = string.Empty;

        [JsonPropertyName("token")]
        public string? Token { get; set; }

        [JsonPropertyName("expiration")]
        public DateTime? Expiration { get; set; }

        [JsonPropertyName("userId")]
        public string? UserId { get; set; }

        [JsonPropertyName("username")]
        public string? Username { get; set; }

        [JsonPropertyName("firstName")]
        public string? FirstName { get; set; }

        [JsonPropertyName("lastName")]
        public string? LastName { get; set; }

        [JsonPropertyName("email")]
        public string? Email { get; set; }

        [JsonPropertyName("phoneNumber")]
        public string? PhoneNumber { get; set; }

        [JsonPropertyName("location")]
        public string? Location { get; set; }

        [JsonPropertyName("profileUrl")]
        public string? ProfileUrl { get; set; }

        [JsonPropertyName("isServiceProvider")]
        public bool? IsServiceProvider { get; set; }

        [JsonPropertyName("roles")]
        public List<string>? Roles { get; set; }

        [JsonPropertyName("data")]
        public object? Data { get; set; }

        // Helper methods to create responses
        public static Response Success(string message = "Operation completed successfully")
        {
            return new Response { Status = "Success", Message = message };
        }

        public static Response Error(string message = "An error occurred")
        {
            return new Response { Status = "Error", Message = message };
        }

        public static Response NotFound(string resource = "Resource")
        {
            return new Response { Status = "Error", Message = $"{resource} not found" };
        }

        public Response WithToken(string token, DateTime expiration)
        {
            Token = token;
            Expiration = expiration;
            return this;
        }
        public Response WithRoles(List<string> roles)
        {
            Roles = roles;
            return this;
        }

    }
}
