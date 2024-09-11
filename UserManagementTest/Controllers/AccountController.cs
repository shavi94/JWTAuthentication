using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using UserManagementTest.Models;

namespace UserManagementTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IConfiguration _config;
        public AccountController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public ActionResult Login([FromBody] Login userLogin)
        {
            var user = Authenticate(userLogin);
            if (user != null)
            {
                var token = GenerateToken(user);

                var refreshToken = GenerateRefreshToken();

                Console.WriteLine("Refresh Token:" + refreshToken);

                CookieOptions options = new CookieOptions();
                options.Expires = DateTime.Now.AddDays(1);

                Response.Cookies.Append("User_TL_Id", user.Id.ToString());

                var response = new LoginResponse
                {
                    access_Token = token,
                    refresh_token = refreshToken
                };
                return Ok(response);
            }

            return NotFound("user not found");
        }

        [AllowAnonymous]
        [HttpPost("Refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshModel model)
        {
            var principal = GetPrincipalsFromExpiredToken(model.AccessToken);

            if (principal?.Identity?.Name is null)
                return Unauthorized();

            int uid = Convert.ToInt32(Request.Cookies["User_TL_Id"]);

            var user = UserConstants.Users.FirstOrDefault(x => x.Username.ToLower() ==
                principal.Identity.Name.ToLower() && x.Id == uid);

            if (user is null)
                return Unauthorized();

            var token = GenerateToken(user);

            var refreshToken = GenerateRefreshToken();

            var response = new LoginResponse
            {
                access_Token = token,
                refresh_token = refreshToken
            };

            return Ok(response);
        }
        private ClaimsPrincipal GetPrincipalsFromExpiredToken(string token)
        {
            var validation = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _config["Jwt:Issuer"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]))
            };

            return new JwtSecurityTokenHandler().ValidateToken(token, validation, out _);
        }
        private Token GenerateToken(UserResponse user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var audiences = _config.GetSection("Jwt:Audiences").Get<string[]>();
            //var audienceString = string.Join(",", audiences);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name,user.Username),
                new Claim(ClaimTypes.Role,user.Role)
            };
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                claims: claims,
                expires: DateTime.Now.AddSeconds(5000),
                signingCredentials: credentials);

            token.Payload.Add("aud", audiences);

            var access_token =  new JwtSecurityTokenHandler().WriteToken(token);

            var tokenObj = new Token
            {
                token = access_token,
                expires_In = token.ValidTo.ToUniversalTime(),
                current_Time = DateTime.Now.ToUniversalTime()
            };

            return tokenObj;

        }
        private UserResponse Authenticate(Login userLogin)
        {
            var currentUser = UserConstants.Users.FirstOrDefault(x => x.Username.ToLower() ==
                userLogin.Username.ToLower() && x.Password == userLogin.Password);
            if (currentUser != null)
            {
                return currentUser;
            }
            return null;
        }
        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];

            using var generator = RandomNumberGenerator.Create();

            generator.GetBytes(randomNumber);

            return Convert.ToBase64String(randomNumber);
        }
    }
}
