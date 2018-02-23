using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Telegram
{
    public class TelegramAuthenticationHandler : AuthenticationHandler<TelegramAuthenticationOptions>
    {
        private readonly ILogger _logger;
        public TelegramAuthenticationHandler(ILogger logger)
        {
            _logger = logger;
        }

        protected async override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {

                IReadableStringCollection query = Request.Query;

                string code = GetFromQuery(query, "code");
                string id = GetFromQuery(query, "id");
                string state = GetFromQuery(query, "state");
                string firstName = GetFromQuery(query, "first_name");


                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;


                //Verify Response

                ClaimsIdentity identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, id));
                identity.AddClaim(new Claim(ClaimTypes.Name, firstName));

                return new AuthenticationTicket(identity, properties);
            }
            catch (Exception)
            {
                return new AuthenticationTicket(null, properties);

            }
        }

        private static string GetFromQuery(IReadableStringCollection query, string name)
        {
            IList<string> values = query.GetValues(name);
            if (values != null && values.Count == 1)
            {
                return values[0];
            }
            return null;
        }

        public override Task<bool> InvokeAsync()
        {
            if (Options.TelegramLoginPath == Request.Path)
            {
                return InvokeLoginPathAsync();
            }
            else if (Options.CallbackPath == Request.Path)
            {
                return InvokeReplyPathAsync();
            }

            return Task.FromResult(false);
        }

        private async Task<bool> InvokeLoginPathAsync()
        {
            string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

            string redirectUri =
               baseUri +
               Options.CallbackPath +
               "?state=" + Request.Query["state"];

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append("<!DOCTYPE html><html><div>");

            stringBuilder.Append("<script async src=\"https://telegram.org/js/telegram-widget.js?3\" ");
            stringBuilder.Append($"data-telegram-login=\"{Options.BotUsername}\" ");
            stringBuilder.Append($"data-size=\"{Options.ButtonStyle.ToString().ToLower()}\" ");
            stringBuilder.Append($"data-auth-url=\"{redirectUri}\" ");

            if (Options.RequestAccess)
            {
                stringBuilder.Append("data-request-access=\"write\" ");
            }

            if (!Options.ShowUserPhoto)
            {
                stringBuilder.Append("data-userpic=\"false\" ");
            }

            stringBuilder.Append("></script>");
            stringBuilder.Append("</div></html>");

            string responce = stringBuilder.ToString();

            await Response.WriteAsync(responce);
            Response.ContentLength = Encoding.UTF8.GetByteCount(responce);

            return true;
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            AuthenticationTicket ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                //_logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }


                ClaimsIdentity grantIdentity = ticket.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, Options.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, Options.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(ticket.Properties, grantIdentity);

            Response.Redirect(ticket.Properties.RedirectUri);

            return true;
        }



        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }
            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.TelegramLoginPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);
                string state = Options.StateDataFormat.Protect(properties);
                redirectUri += "?state=" + state;
                Response.Redirect(redirectUri);
            }

            return Task.FromResult<object>(null);
        }
    }
}