namespace UnityHub.Infrastructure.Interface
{
    public interface IEmailSender<TUser>
    {
        Task SendEmailAsync(string from, string to, string subject, string body);
    }
}
