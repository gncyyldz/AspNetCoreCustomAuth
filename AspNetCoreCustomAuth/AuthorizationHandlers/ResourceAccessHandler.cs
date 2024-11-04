using AspNetCoreCustomAuth.AuthorizationRequirements;
using Microsoft.AspNetCore.Authorization;
using System.Text.Json;

namespace AspNetCoreCustomAuth.AuthorizationHandlers
{
    public sealed class ResourceAccessHandler : AuthorizationHandler<ResourceAccessRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ResourceAccessRequirement requirement)
        {
            var resourceAccessClaim = context.User.FindFirst("resource_access");

            if (resourceAccessClaim != null)
            {
                using var jsonDocument = JsonDocument.Parse(resourceAccessClaim.Value);
                var root = jsonDocument.RootElement;

                if (root.TryGetProperty("realm-management", out var realmManagement))
                    if (realmManagement.TryGetProperty("roles", out var rolesElement) && rolesElement.ValueKind == JsonValueKind.Array)
                    {
                        var roles = rolesElement.EnumerateArray().Select(role => role.GetString());
                        if (roles.Contains(requirement.Role))
                            context.Succeed(requirement);
                    }
            }

            return Task.CompletedTask;
        }
    }
}
