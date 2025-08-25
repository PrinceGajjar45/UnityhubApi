namespace UnityHub.Infrastructure.Interface
{
    public interface IEmailSender
    {
        void SendEmailAsync(string from, string to, string subject, string body);
    }
}
