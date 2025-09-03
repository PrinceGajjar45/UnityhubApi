namespace UnityHub.API.Authentication
{
    /// <summary>
    /// Basic user details for API responses.
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
        public string Role { get; set; } // Added for role-based response
    }
}