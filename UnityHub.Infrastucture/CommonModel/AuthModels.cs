namespace UnityHub.Infrastructure.CommonModel
{
    public class LoginModel
    {
        public string PhoneNumber { get; set; }
        public string Password { get; set; }
    }

    public class RegisterModel
    {
        public string Username { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool IsServiceProvider { get; set; }
        public string Role { get; set; }
        public string Address { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Country { get; set; }
        public string ZipCode { get; set; }
        public decimal? Latitude { get; set; }
        public decimal? Longitude { get; set; }
        public string ProfileUrl { get; set; }
        public string PhoneNumber { get; set; }
        public string Email { get; set; } // Optional, not used for login
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
    }

    public class ForgotPassword
    {
        public string PhoneNumber { get; set; }
    }

    public class ResetPassword
    {
        public string Token { get; set; }
        public string PhoneNumber { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
    }

    public class ChangeUserPassword
    {
        public string PhoneNumber { get; set; }
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmNewPassword { get; set; }
    }

    public class ReSentVerificationCode
    {
        public string PhoneNumber { get; set; }
    }

    public class UpdateUserProfile
    {
        public string UserName { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PhoneNumber { get; set; }
        public string Location { get; set; }
        public string ProfileUrl { get; set; }
        public string Address { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Country { get; set; }
        public string ZipCode { get; set; }
        public decimal? Latitude { get; set; }
        public decimal? Longitude { get; set; }
    }
}