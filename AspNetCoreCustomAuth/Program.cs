using AspNetCoreCustomAuth.AuthenticationHandlers;
using AspNetCoreCustomAuth.AuthorizationHandlers;
using AspNetCoreCustomAuth.AuthorizationRequirements;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpContextAccessor();

#region Geleneksel Authentication Yapýlanmasý
//builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//    .AddJwtBearer(options =>
//    {
//        options.TokenValidationParameters = new()
//        {
//            ValidateAudience = true,
//            ValidateIssuer = true,
//            ValidateLifetime = true,
//            ValidateIssuerSigningKey = true,
//            ValidIssuer = builder.Configuration["JWT:Issuer"],
//            ValidAudience = builder.Configuration["JWT:Audience"],
//            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:SecurityKey"])),
//            ClockSkew = TimeSpan.Zero
//        };
//    });
#endregion
#region Manuel Authentication Yapýlanmasý
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "Manual";
    options.DefaultChallengeScheme = "Manual";
}).AddScheme<AuthenticationSchemeOptions, ManualAuthenticationHandler>("Manual", null);
#endregion
#region Özel Gereksinim Yapýlanmasý(Rol Tabanlý Yetkilendirme)
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("UserRoleControl", policy => policy.Requirements.Add(new ResourceAccessRequirement("user")));
});

builder.Services.AddSingleton<IAuthorizationHandler, ResourceAccessHandler>();
#endregion

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/get-token-claims", (HttpContext context) => context.User.Claims.Select(c => c.Type))
    .RequireAuthorization(policy => policy.RequireAuthenticatedUser());

app.MapGet("/", () => Results.Ok())
    .RequireAuthorization("UserRoleControl");

app.Run();
