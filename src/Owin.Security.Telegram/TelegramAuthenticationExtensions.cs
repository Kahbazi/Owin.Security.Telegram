using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Telegram
{
    public static class TelegramAuthenticationExtensions
    {
        public static IAppBuilder UseTelegramAuthentication(this IAppBuilder app, TelegramAuthenticationOptions options)
        {
            return app.Use<TelegramAuthenticationMiddleware>(app, options);
        }
    }
}
