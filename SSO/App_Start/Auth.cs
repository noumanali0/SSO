using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using SSO.Models;
using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SSO.App_Start
{
    public partial class Auth
    {


        public CookieConsentViewModel Vm { get; set; } = new CookieConsentViewModel() { ShowConsent = true };

        private static string appId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];
        private static string appSecret = System.Configuration.ConfigurationManager.AppSettings["AppSecret"];
        private static string redirectUri = System.Configuration.ConfigurationManager.AppSettings["redirectUri"];
        private static string graphScopes = System.Configuration.ConfigurationManager.AppSettings["AppScopes"];

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = appId,
                    Authority = "https://login.microsoftonline.com/common/v2.0",
                    Scope = $"openid email profile offline_access {graphScopes}",
                    RedirectUri = redirectUri,
                    PostLogoutRedirectUri = redirectUri,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        // For demo purposes only, see below
                        ValidateIssuer = false

                        // In a real multi-tenant app, you would add logic to determine whether the
                        // issuer was from an authorized tenant
                        //ValidateIssuer = true,
                        //IssuerValidator = (issuer, token, tvp) =>
                        //{
                        //  if (MyCustomTenantValidation(issuer))
                        //  {
                        //    return issuer;
                        //  }
                        //  else
                        //  {
                        //    throw new SecurityTokenInvalidIssuerException("Invalid issuer");
                        //  }
                        //}
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = OnAuthenticationFailedAsync,
                        AuthorizationCodeReceived = SetClaims,

                        SecurityTokenValidated = OnSecurityTokenValidated,

                        //SecurityTokenValidated = notification =>
                        //{

                        //    notification.AuthenticationTicket.Identity.AddClaim(new Claim("Role", "Manager"));
                        //    notification.AuthenticationTicket.Identity.AddClaim(new Claim("View", "Manager"));
                        //    notification.AuthenticationTicket.Identity.AddClaim(new Claim("Now", "Manager"));
                        //    notification.AuthenticationTicket.Identity.AddClaim(new Claim("Me", "Manager"));
                        //    notification.AuthenticationTicket.Identity.AddClaim(new Claim("To", "Manager"));



                        //    return Task.FromResult(0);
                        //},

                    }
                }
            );
        }

        private static Task OnAuthenticationFailedAsync(AuthenticationFailedNotification<OpenIdConnectMessage,
            OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            string redirect = "/";
            if (notification.ProtocolMessage != null && !string.IsNullOrEmpty(notification.ProtocolMessage.ErrorDescription))
            {
                redirect += $"&debug={notification.ProtocolMessage.ErrorDescription}";
            }
            notification.Response.Redirect(redirect);
            return Task.FromResult(0);
        }

        private async Task OnAuthorizationCodeReceivedAsync(AuthorizationCodeReceivedNotification notification)
        {
            var idClient = ConfidentialClientApplicationBuilder.Create(appId)
                .WithRedirectUri(redirectUri)
                .WithClientSecret(appSecret)
                .Build();


            try
            {
                string[] scopes = graphScopes.Split(' ');

                var result = await idClient.AcquireTokenByAuthorizationCode(
                    scopes, notification.Code).ExecuteAsync();

                Vm.Token = result.AccessToken;

                Vm.ShowConsent = true;

                Vm.ConsentGiven = true;


                Debug.WriteLine($"Token Here {result.AccessToken}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }


        }

        private Task OnSecurityTokenValidated(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> n)
        {
            var claimIdentity = new ClaimsIdentity(n.AuthenticationTicket.Identity);
            // Custom code...
            claimIdentity.Claims.Append(new Claim("TEST", "1234"));
            n.OwinContext.Authentication.SignIn(claimIdentity);
            return Task.FromResult(0);
        }


        private Task SetClaims(AuthorizationCodeReceivedNotification notification)
        {
            var identity = new ClaimsIdentity(notification.AuthenticationTicket.Identity.AuthenticationType);
            identity.AddClaim(new Claim("Test", "1234"));

            var newTicket = new AuthenticationTicket(identity, notification.AuthenticationTicket.Properties);
            notification.AuthenticationTicket = newTicket;
            return Task.CompletedTask;
        }


        //private Task OnSecurityTokenValidated(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> n)
        //{
        //    var claimsPrincipal = new ClaimsPrincipal(n.AuthenticationTicket.Identity);
        //    // Custom code...
        //    // TEST:





        //    n.OwinContext.Response.Context.Authentication.User = claimsPrincipal;
        //    n.OwinContext.Request.User = claimsPrincipal;
        //    n.OwinContext.Authentication.User = claimsPrincipal;
        //    return Task.FromResult(0);
        //}




    }
}