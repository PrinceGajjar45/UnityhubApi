namespace UnityHub.API.Authentication
{
    public class TwoFactorRequestModel
    {
        public string PhoneNumber { get; set; }
        public string OTP { get; set; }
    }
}
