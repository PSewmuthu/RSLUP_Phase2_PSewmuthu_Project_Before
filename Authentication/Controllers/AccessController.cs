using Microsoft.AspNetCore.Mvc;

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Authentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Authentication.Controllers
{
    public class AccessController : Controller
    {
        public IActionResult Login()
        {
            ClaimsPrincipal claimUser = HttpContext.User;

            if (claimUser.Identity.IsAuthenticated)
                return RedirectToAction("Index", "Home");

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(VMLogin modelLogin)
        {
            if (modelLogin.Email == "test@email.com" && modelLogin.Password == "password123")
            {
                List<Claim> claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.NameIdentifier, modelLogin.Email),
                    new Claim("OtherProperties", "Example Role")
                };

                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims,
                    CookieAuthenticationDefaults.AuthenticationScheme);

                AuthenticationProperties properties = new AuthenticationProperties()
                {
                    AllowRefresh = true,
                    IsPersistent = modelLogin.KeepLoggedIn
                };

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity), properties);

                return RedirectToAction("Index", "Home");
            }

            ViewData["ValidateMessage"] = "user not found";
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user_email = model.Email;

                // Generate the reset password token
                var token = "soifir02h8t2'29h[f80434-2=32-39h4f492=t3t1]t-3t4-4uf";

                // Build the password reset link
                var passwordResetLink = Url.Action("ResetPassword", "Account",
                        new { email = model.Email, token = token }, Request.Scheme);

                // To avoid account enumeration and brute force attacks, don't
                // reveal that the user does not exist or is not confirmed
                return View("ForgotPasswordConfirmation");
            }

            return View(model);
        }
    }
}
