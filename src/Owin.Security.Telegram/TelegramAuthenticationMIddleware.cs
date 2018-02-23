using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Telegram
{

    public class TelegramAuthenticationMiddleware : AuthenticationMiddleware<TelegramAuthenticationOptions>
    {
        private readonly ILogger _logger;
        public TelegramAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, TelegramAuthenticationOptions options)
            : base(next, options)
        {
            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtecter = app.CreateDataProtector(
                    typeof(TelegramAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtecter);
            }

            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            _logger = app.CreateLogger<TelegramAuthenticationMiddleware>();
        }

        protected override AuthenticationHandler<TelegramAuthenticationOptions> CreateHandler()
        {
            return new TelegramAuthenticationHandler(_logger);
        }
    }
}
