namespace UnityHub.Core.CommonModel
{
    /// <summary>
    /// Unified API response wrapper including status code and data.
    /// </summary>
    public class CustomApiResponse<T>
    {
        public int StatusCode { get; set; }
        public string Message { get; set; }
        public T Data { get; set; }
        public string Token { get; set; }
        public DateTime? Expiration { get; set; }
    }

    /// <summary>
    /// Basic user details for API responses (moved from API to Core).
    /// </summary>
    public class UserBasicDetails
    {
        public string UserId { get; set; }
        public string Username { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string Location { get; set; }
        public string ProfileUrl { get; set; }
        public bool IsServiceProvider { get; set; }
        public string Role { get; set; }
    }
}
