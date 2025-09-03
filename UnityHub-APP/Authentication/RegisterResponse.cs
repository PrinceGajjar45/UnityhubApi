namespace UnityHub.API.Authentication
{
    /// <summary>
    /// Response model for user registration, including token and user basic details.
    /// </summary>
    public class RegisterResponse
    {
        /// <summary>
        /// The JWT token for the registered user.
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        /// The token expiration date/time.
        /// </summary>
        public DateTime Expiration { get; set; }

        /// <summary>
        /// The user's unique identifier.
        /// </summary>
        public string UserId { get; set; }

        /// <summary>
        /// The user's username.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// The user's first name.
        /// </summary>
        public string FirstName { get; set; }

        /// <summary>
        /// The user's last name.
        /// </summary>
        public string LastName { get; set; }

        /// <summary>
        /// The user's email address.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// The user's phone number.
        /// </summary>
        public string PhoneNumber { get; set; }

        /// <summary>
        /// The user's location.
        /// </summary>
        public string Location { get; set; }

        /// <summary>
        /// The user's profile URL.
        /// </summary>
        public string ProfileUrl { get; set; }

        /// <summary>
        /// Indicates if the user is a service provider.
        /// </summary>
        public bool IsServiceProvider { get; set; }
    }
}
