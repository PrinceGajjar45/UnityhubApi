using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace UnityHub.Infrastructure.Interface
{
    public interface IEmailSender
    {
        void SendEmail(string from, string to, string subject, string body);
    }
}
