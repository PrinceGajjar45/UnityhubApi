namespace UnityHub.API.Authentication
{
    public class TwoFactorRequestModel
    {
        public string Email { get; set; }
        public string OTP { get; set; }
    }
}
