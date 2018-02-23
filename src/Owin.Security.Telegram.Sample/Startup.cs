using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Owin.Security.Telegram.Sample.Startup))]
namespace Owin.Security.Telegram.Sample
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
