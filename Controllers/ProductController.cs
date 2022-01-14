using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace UserControl.Controllers
{
    [ApiController]
    [Route("v1/products")]
    public class ProductController : ControllerBase
    {
        [HttpGet]
        [Authorize(Policy = "EmployeePolicy")]
        public async Task<IActionResult> GetLoggedUserAsync([FromServices] UserManager<IdentityUser> userManager)
        {
            var a = HttpContext.User.Claims;
            var userId = a.First(c => c.Type == ClaimTypes.NameIdentifier).Value;
            var user = await userManager.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == userId);
            if(user == null)
            {
                return NotFound("Usuãrio logado não encontrado");
            }

            return Ok(user);
        }
    }
}