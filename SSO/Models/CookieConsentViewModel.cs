namespace SSO.Models
{
    public class CookieConsentViewModel
    {
        public bool ShowConsent { get; set; }
        public bool ConsentGiven { get; set; }

        public string Token { get; set; }
    }
}