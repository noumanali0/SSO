using Microsoft.Owin;
using Owin;
using SSO.App_Start;



[assembly: OwinStartup(typeof(SSO.Startup))]

namespace SSO
{
    public partial class Startup
    {
        Auth auth;
        public void Configuration(IAppBuilder app)
        {
            auth = new Auth();
            auth.ConfigureAuth(app);
        }
    }
}