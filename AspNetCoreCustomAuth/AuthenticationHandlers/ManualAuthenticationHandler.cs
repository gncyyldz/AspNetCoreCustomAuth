using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace AspNetCoreCustomAuth.AuthenticationHandlers
{
    public class ManualAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        readonly IConfiguration _configuration;
        readonly IHttpContextAccessor _httpContextAccessor;

        public ManualAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            IConfiguration configuration,
            IHttpContextAccessor httpContextAccessor)
            : base(options, logger, encoder)
        {
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string authenticationScheme = "Manual";

            JwtSecurityTokenHandler tokenHandler = new();
            var key = Encoding.ASCII.GetBytes(_configuration["JWT:SecurityKey"]);

            string token = _httpContextAccessor.HttpContext.Request.Headers[HeaderNames.Authorization];
            token = token?.Replace("Bearer ", "");

            ClaimsPrincipal? claimsPrincipal = null;
            try
            {
                claimsPrincipal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _configuration["JWT:Issuer"],
                    ValidAudience = _configuration["JWT:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecurityKey"])),
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var ticket = new AuthenticationTicket(claimsPrincipal, authenticationScheme);
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }
            catch
            {

            }

            return Task.FromResult(AuthenticateResult.Fail(string.Empty));
        }
    }
}