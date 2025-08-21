namespace UnityHub.API.Authentication
{
    public class ChangeUserPasswordModel
    {
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmNewPassword { get; set; }
        public string Email { get; set; }
    }
}
