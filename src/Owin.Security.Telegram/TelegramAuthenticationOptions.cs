using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Telegram
{
    public class TelegramAuthenticationOptions : AuthenticationOptions
    {
        public TelegramAuthenticationOptions()
            : base("Telegram")
        {
            AuthenticationMode = AuthenticationMode.Passive;
            Description.Caption = "Telegram";
            CallbackPath = new PathString("/signin-telegram");
            TelegramLoginPath = new PathString("/login-telegram");
        }

        public string BotUsername { get; set; }
        public ButtonStyle ButtonStyle { get; set; }

        public PathString CallbackPath { get; set; }
        public bool RequestAccess { get; set; }
        public bool ShowUserPhoto { get; set; }
        public PathString TelegramLoginPath { get; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public string SignInAsAuthenticationType { get; set; }
    }
}