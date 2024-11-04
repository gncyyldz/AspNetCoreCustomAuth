using Microsoft.AspNetCore.Authorization;

namespace AspNetCoreCustomAuth.AuthorizationRequirements
{
    public sealed record ResourceAccessRequirement(string Role) : IAuthorizationRequirement
    {

    }
}
