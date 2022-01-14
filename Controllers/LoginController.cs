using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using UserControl.ViewModels;

namespace UserControl.Controllers
{
    [ApiController]
    [Route("v1/login")]
    [AllowAnonymous]
    public class LoginController : ControllerBase
    {
        [HttpPost]
        public async Task<IActionResult> LoginAsync([FromServices] UserManager<IdentityUser> userManager,
                                                    [FromServices] IConfiguration configuration,
                                                    LoginRequestViewModel loginRequestViewModel)
        {
            var user = await userManager.FindByEmailAsync(loginRequestViewModel.Email);
            if (user == null)
            {
                return BadRequest();
            }

            if (!userManager.CheckPasswordAsync(user, loginRequestViewModel.Password).Result)
            {
                return BadRequest();
            }

            var claims = await userManager.GetClaimsAsync(user);
            var subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Email, loginRequestViewModel.Email),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
            });
            subject.AddClaims(claims);

            var key = Encoding.ASCII.GetBytes(configuration["JwtBearerTokenSettings:SecretKey"]);
            var tokenDescription = new SecurityTokenDescriptor
            {
                Subject = subject,
                SigningCredentials =
                    new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = configuration["JwtBearerTokenSettings:Audience"],
                Issuer = configuration["JwtBearerTokenSettings:Issuer"],
                Expires = DateTime.UtcNow.AddHours(1)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescription);

            return Ok(
                new { token = tokenHandler.WriteToken(token) }
            );
        }
    }
}