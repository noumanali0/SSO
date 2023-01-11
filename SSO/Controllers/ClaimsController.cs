using System.Web;
using System.Web.Mvc;

namespace SSO.Controllers
{
    [Authorize]
    public class ClaimsController : Controller
    {


        // GET: Claims

        public ClaimsController()
        {

        }

        public ActionResult Index()
        {

            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;
            var _context = HttpContext.GetOwinContext();
            var principal = _context.Authentication.User;


            //You get the user’s first and last name below:
            ViewBag.Name = userClaims?.FindFirst("name")?.Value;

            // The 'preferred_username' claim can be used for showing the username
            ViewBag.Username = userClaims?.FindFirst("preferred_username")?.Value;

            var test = principal.FindFirst("TEST")?.Value;

            // The subject/ NameIdentifier claim can be used to uniquely identify the user across the web
            ViewBag.TokenEx = test;





            // TenantId is the unique Tenant Id - which represents an organization in Azure AD


            return View();
        }



    }
}