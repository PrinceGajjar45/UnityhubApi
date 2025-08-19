namespace UnityHub.API.Authentication
{
    public class TwoFactorResponseModel
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; }
        public string TempToken { get; set; }
    }
}
