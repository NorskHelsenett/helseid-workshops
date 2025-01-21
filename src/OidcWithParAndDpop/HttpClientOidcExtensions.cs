using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using IdentityModel;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using Microsoft.AspNetCore.WebUtilities;

namespace OidcWithParAndDPoP;

public static class HttpClientOidcExtensions
{
    public static async Task<PushedAuthorizationResponse> GetPushedAuthorizationResponseAsync(
        this HttpClient httpClient,
        string pushedAuthorizationRequestEndpoint,
        string clientId,
        string redirectUri,
        ClientAssertion clientAssertion,
        AuthorizeState authorizeState,
        string[]? scopes = null,
        string[]? resources = null)
    {
        // Sets the pushed authorization request parameters:
        var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(authorizeState.CodeVerifier));
        var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);
        // Setup a client assertion - this will authenticate the client (this application)

        var pushedAuthorizationRequest = new PushedAuthorizationRequest
        {
            Resource = resources == null ? new List<string>() : resources,
            Address = pushedAuthorizationRequestEndpoint,
            ClientId = clientId,
            ClientAssertion = clientAssertion,
            RedirectUri = redirectUri,
            Scope = scopes == null ? "" : string.Join(' ', scopes),
            ResponseType = OidcConstants.ResponseTypes.Code,
            ClientCredentialStyle = ClientCredentialStyle.PostBody,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = OidcConstants.CodeChallengeMethods.Sha256,
            State = authorizeState.State,
        };

        // Calls the /par endpoint in order to get a request URI for the /authorize endpoint
        return await httpClient.PushAuthorizationAsync(pushedAuthorizationRequest);
    }
}