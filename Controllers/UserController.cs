using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using UserControl.ViewModels;

namespace UserControl.Controllers
{
    [ApiController]
    [Route("v1/users")]
    public class UserController : ControllerBase
    {
        [HttpGet]
        public async Task<IActionResult> GetAsync([FromServices] UserManager<IdentityUser> userManager)
        {
            var users = await userManager.Users.AsNoTracking().ToListAsync();

            if(!users.Any())
            {
                return NoContent();
            }

            return Ok(users);
        }

        [HttpGet]
        [Route("{id}")]
        [Authorize(Policy = "EmployeePolicy")]
        public async Task<IActionResult> GetByIdAsync([FromServices] UserManager<IdentityUser> userManager,
                                                      string id)
        {
            var user = await userManager.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id);

            if(user ==  null)
            {
                return NotFound();
            }

            return Ok(user);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> PostAsync([FromServices] UserManager<IdentityUser> userManager,
                                                   CreateUserViewModel createUserViewModel)
        {
            var user = new IdentityUser() { UserName = createUserViewModel.Email, Email = createUserViewModel.Email };
            var result = await userManager.CreateAsync(user, createUserViewModel.Password);

            if(!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            var userClaims = new List<Claim>
            {
                new Claim("Cpf", createUserViewModel.Cpf),
                new Claim("EmployeeCode", createUserViewModel.EmployeeCode)
            };
            await userManager.AddClaimsAsync(user, userClaims);
            return Created($"/users/{user.Id}", user.Id);
        }

        [HttpPut]
        [Route("{id}")]
        [Authorize(Policy = "EmployeePolicy")]
        public async Task<IActionResult> PutAsync([FromServices] UserManager<IdentityUser> userManager,
                                                  UpdateUserViewModel updateUserViewModel,
                                                  string id)
        {
            var user = await userManager.Users.SingleOrDefaultAsync(u => u.Id == id);

            if(user ==  null)
            {
                return NotFound();
            }

            user.PhoneNumber = updateUserViewModel.PhoneNumber;
            var result = await userManager.UpdateAsync(user);

            if(!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Created($"/users/{user.Id}", user.Id);
        }

        [HttpDelete]
        [Route("{id}")]
        public async Task<IActionResult> DeleteAsync([FromServices] UserManager<IdentityUser> userManager,
                                                      string id)
        {
            var user = await userManager.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id);

            if(user ==  null)
            {
                return NotFound();
            }

            var result = await userManager.DeleteAsync(user);
            if(!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            
            return Ok(user);
        }
    }
}