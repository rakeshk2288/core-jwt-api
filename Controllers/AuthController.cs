using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace core_jwt_api.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        public record AuthInput(string Username = "admin", string Password = "admin");
        public record AuthOutput(string Token);
        public record AuthError(string ErrorMessage);

        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            this._configuration = configuration;
        }

        [HttpPost]
        public IActionResult Post([FromBody] AuthInput authInput)
        {
            try
            {
                if (!authInput.Username.Equals("admin") && !authInput.Password.Equals("admin"))
                    return NotFound("Username/ Password is invalid");

                var token = GenerateToken(authInput);
                return Ok(new AuthOutput(token));
            }
            catch (Exception ex)
            {
                return BadRequest(new AuthError(ex.Message));
            }
        }

        private string GenerateToken(AuthInput authInput)
        {
            var secreyKey = _configuration["JWT:SecretKey"];
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secreyKey));
            var signingCred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new Claim[]
            {
                new Claim(ClaimTypes.Name,authInput.Username),
                new Claim("city", "blr")
            };

            var jwtToken = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                expires: DateTime.UtcNow.AddMinutes(5),
                claims: claims,
                signingCredentials: signingCred
                );

            var token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            return token;
        }
    }
}

