using IdentityModel.OidcClient;

namespace oidc.example;

public static class LoginResultExtensions
{
    public static LoginResult ValidateIdentityClaims(this LoginResult loginResult)
    {
        // The claims from the identity token has ben set on the User object;
        // We validate that the user claims match the required security level:
        if (loginResult.User.Claims.Any(c => c is
            {
                Type: "helseid://claims/identity/security_level",
                Value: "4",
            }))
        {
            return loginResult;
        }

        return new LoginResult("Invalid security level", "The security level is not at the required value");
    }
}