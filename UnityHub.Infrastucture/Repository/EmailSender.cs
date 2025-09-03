using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Mail;
using UnityHub.Infrastructure.Data;
using UnityHub.Infrastructure.Interface;



namespace UnityHub.Infrastructure.Repository
{
    public class EmailSender : IEmailSender<ApplicationUser>
    {
        private readonly IConfiguration _configuration;
        public EmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public Task SendEmailAsync(string from, string to, string subject, string body)
        {
            try
            {
                var emailConfig = _configuration.GetSection("EmailConfiguration");

                if (emailConfig == null)
                {
                    throw new ArgumentNullException("EmailConfiguration section is missing in configuration");
                }

                var host = emailConfig["Host"];
                var port = int.Parse(emailConfig["Port"]);
                var username = emailConfig["Username"];
                var password = emailConfig["Password"];

                if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                {
                    throw new ArgumentException("Email configuration values are missing or invalid");
                }

                var message = new MailMessage(from, to, subject, body)
                {
                    From = new MailAddress(from),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true,
                };

                message.To.Add(to);

                using (var client = new SmtpClient(host))
                {
                    try
                    {
                        client.Port = 587;
                        client.Credentials = new NetworkCredential(username, password);
                        client.EnableSsl = true;
                        client.DeliveryMethod = SmtpDeliveryMethod.Network;
                        client.Send(message);
                    }
                    catch (SmtpException smtpEx)
                    {
                        throw new ApplicationException("Failed to send email due to SMTP error", smtpEx);
                    }
                    catch (System.Exception ex)
                    {
                        throw new ApplicationException("Failed to send email", ex);
                    }
                }
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("Invalid port number in email configuration", ex);
            }
            catch (System.Exception ex)
            {
                throw new ApplicationException("Email sending failed due to initialization error", ex);
            }
            return Task.CompletedTask;
        }
    }
}