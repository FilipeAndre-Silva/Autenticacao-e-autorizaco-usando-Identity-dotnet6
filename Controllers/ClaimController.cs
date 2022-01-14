using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace UserControl.Controllers
{
    [ApiController]
    [Route("v1/claims")]
    public class ClaimController : ControllerBase
    {
        [HttpGet]
        [Route("{id}")]
        public async Task<IActionResult> GetByUserIdAsync([FromServices] UserManager<IdentityUser> userManager,
                                                          string id)
        {
            var user = await userManager.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id);
            var claims = await userManager.GetClaimsAsync(user);

            if(!claims.Any())
            {
                return NoContent();
            }

            return Ok(claims);
        }
    }
}