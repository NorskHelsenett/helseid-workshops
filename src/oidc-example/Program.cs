// See https://aka.ms/new-console-template for more information

using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using IdentityModel;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using IdentityModel.OidcClient.Browser;
using IdentityModel.OidcClient.DPoP;
using Microsoft.IdentityModel.Tokens;

namespace oidc.example;

class Program
{
    private const string JwkPrivateKey = """
                                         {
                                             "alg": "PS256",
                                             "d": "C0lPai9JgsAJCjWr5c3_fWKREC5WSBICrBrpkPzlxmpjgj5yVlHkq5achfGkggqR1EGoz9MYkULq0Cx3F6waHpMPvfl2DA0h_NXB5RQ3fBkRYVdCgrC0ze-xl5E1CZYRXtIXrzNQKea9VvGFWPPdbtwZSzoUfsQxiPe3QIgwftCbYYX0JYuqcANYzqt3baCZH4X5tyZD_cbkh-B4w9RBEmV-bD_d8c1aIwjUFILKYQHgzJd5_sott3OtBc6wsBZ_FzzIZVRG4vJNg235kOg23I7q6x5eAY3DTO2lEEZiXxR2NPkuvH4WC7ivrmRieIpj_V5j_SOZHwdEFfyrSaqbc_ZMEz1Rm_Cf_8AKRLNcQr35x86lT4vHL7fIM4g5kXphR8l7xzoGZhLHF8XnwEUruGvjSHuZTUUKy8qXWqR-faYsm6BX9qGsHfFiPmWYGZpccWAwJZBocjU8E-x5lRS_WseNH3Vml8l642uNSOKkZ8BiH_IRFBDLLBkgkMFszVVCLTlSNf5rBdp6N4CScMwcDot8ueU3a6dAvHk3TNHKQjnjAxkDNiIaT8arzbSZmWpjFTc2DPjXQd0Zx3TD9DMxS30ew1vpgpB7g0FHHRLV33OyHacJbusR25UqvPYT1jLsXVCVj70WjoyxqMhYGRoSSQZk9bxyqydKciCSzH-iaYE",
                                             "dp": "wJxws-cFtGNBsFaLtzmCpQXd40sEvpIvMDk-oLkAAycVItBrn3QQzxZk4DCGke79ra-SfLNSBLjkAKqiAYcHLbuIM_1f1_7qExvTnBmEUPlpQuNW2c2VkJhbb1w7hinHliYlh6dZockLx-0Jlb4Fp-rws7qglgjAS_xx0go6RAGcYjz7NvP9oP5Lk__WODtzq4ATobRDfepKGrLk_QXcDznPCdbVmazddFrRSerFwOKKoWX9NQih-lq6SHQs_QfC9xQjUzGpUWzqvaVgvdPu2kihJTJe2nvzxm7o1N_03vWzQVoO2ZMHhC59a6x5a0aURBVqzUjeBq39P3b6EhJwgQ",
                                             "dq": "cQsvlQjpapXYhdjT47_j8TC1hbrxwkborNZy0kqq_e2V28c_V9mRS2JCVuGtpm5e-7_0v3-lEs-vrqLAs6yzdD6ScyFd_rdS12_rLIBJmDUb3KwMClt9DrealExC2-380WE4qUucsZgO1i3yXQyB6BchcrFAH9TXfuRXGX9BsFIfOpsnfHtQVDP7v5t5mVnwqCqC2sp-pfpwp-mCXhwO8orD9X1bIwmwR6H8FQy7YWMacBKL8XtTfRn3GXdRdXA15CITn_CsvwhNyTtcW4Ui35WQPBR_yWRcVDOfWQFx3H49NV5P3B1rbMZQb3hl20tFyLsfUpvRzcjvEZVpZPE0aQ",
                                             "e": "AQAB",
                                             "kty": "RSA",
                                             "n": "sxoCv21xy2BJ3K5AVzrBfqB6_Jb3Yh4EQNVBWojXdu_VD88bmxRI1_Vi8yHt-SfAVDAF9cbcudMtikC4ZfrvZ1aBsFQjUqeqifoa1ycKQ0eOoYaB0_4Wok1CBDvQN1HArHSBHafDiPAsEtXXWxEGFV3iHJFsnfbVldJsIWrkg6qITnmreIGNG72-55bLP_zIKaP5j6Xb_6mG5QfgPXiqoLcJHJQOlnMoP4jD63QmsBbXJ297vKGW5jZHM3ejpY1YkVSS2n5FHmPw1oZls9s6P42_J1_FpRpR4Cqa47cffgDlW3BmbFokMtqUbpvrSrNuyqCOtKJ7u7w8JI6WJG5tK2MW_fQk-PeRfQGWnAK-SjwEOmBEWE6rcSuFTetBSV7zpp4uvj7RUUn1RIzWzYGEAYWbbfXyYKuLoZ_1absw3eQH_WC_eKrjbywn1_LVUr3H2yPpYXSjZmqvlKS8YWPnLfCExXeaVjfJ5SEVe_l_GUPNlTbNowonaEDuodObbLeASI6SXzJei2JDUVCsuHmXwpCYYvlnERCcUCiteVV9GLE7Uw_Po5pZ-eT7fkGeh2Y1qjtdrfeZcGdNjyQqw4VrkBW9edx7kz5Dun72oDmeWiM7PbGEnT49USfyQxHy_shh2xXmkTvAGo5ugsiZCOf89NUTpF1XQSuQofpcSeNq2CU",
                                             "p": "61XaFAPiECouVyjA_sUNax_fDiBoDSET_Co0LKau9NeNnkXuT90uFd1NfJi85N2LXomsLx_LRaHqXkW41zGsHCvq5xII-DW7FUVuXfqSGkRw3W9BAQ6MfQ1x1zE5epd2qXdDG3OiD4YdNCUjblslJ57eu6q0azM1EhFo4Zf8hF-gaadg_oMM1Cwj4dWGROpbB0lgE706EdReWbOvExlyuaym2ZztPbyFKaSEJgdbm_xe13zq2QViM7DuCWArwunoSyLinJN_Ds0U2Ecfs25Ny5Cy-6PoQWEq5MQJqKefqenpyJiI5ZelgcEErFb7X8XPSLNBWu6BRQ41M-6na38rgQ",
                                             "q": "wtQR1BUMSihHmhwnBh_2a6qSnhpcKLiXQhdYWGrxh5rFzWGLT5FUakkYxNLiVqhQv0vLfCGxJEPS6N73md4yxHXVD07QrEX4zTeV4DhgWudEJ9quaHRGdgHQHqMoI41JqOzvQPDkjdb9eGQgHpVr8t2bz0bbBTeeAPfk8uNUIvq7e_TdkaMZwRiZaVPMKtdBri8sRDhYVIKmaOcemihYv5WDSzU6sbyQuZwJsBt4bVJA1t9nEhrT6B-yXCrIaQi74rN60rGuibjAZAWVwf4hju2ljobAZKJrh_NQPTAZ1oDQBgB-NJLr1N8dTBflGI2nS8wwZyi0tDoXaw8q5nLOpQ",
                                             "qi": "PgMlHvWtSkQ0lLsc6NVoi0tJW-wKaQHGaYGbE-3IrnYyxqI6EttszdA5NKAL6zL6I1B6QyMRD3GYT9KpymP6ANdarPknGVF7gUI3myh2hYRKCO18StO-7nUxYqf_YeemF5GVgXwsHyGBcvXv0H5g3pNKZwag9zyxt-RsRESQ6p5xjNryMKSKtjnZGI8pQWOIWIQae13UEUo2J7hIjVBZuaMIGhaljSJdjUa_GSbbs0kbF-bdCcYcG0qDwTor0IPxQR4CtstBRDNYPu_rieBu1cQuamhGxe9XWdK-3XKJmQq26TqrO2B1xW0fC_qwq72AieGiOUYtbyIifQTlstqn5w"
                                         }
                                         """;
    
    private const string AuthorityUrl = "https://helseid-sts.test.nhn.no";
    private const string ClientId = "e1df09c7-6ccf-4a38-a3f7-545ac665b10a";
    private const int LocalhostPort = 8089;
    private static readonly string RedirectUri = $"http://localhost:{LocalhostPort.ToString()}/callback";
    
    private const string ApiResource1 = "nhn:kjernejournal";
    private const string ApiResource2 = "nhn:phr";
    private const string ScopeApiResource1 = "nhn:kjernejournal/tillitsrammeverk";
    private const string ScopeApiResource2ReadDocument = "nhn:phr/mhd/read-document";
    private const string ScopeApiResource2ReadDocumentReferences = "nhn:phr/mhd/read-documentreferences";

    private const string OrganizationNumber = "";
    
    private static readonly string[] AllScopes = 
        ["openid", "profile", "offline_access", "helseid://scopes/identity/security_level", ScopeApiResource1, ScopeApiResource2ReadDocument, ScopeApiResource2ReadDocumentReferences];

    private static readonly string[] IdentityScopes =
        ["openid", "profile", "offline_access", "helseid://scopes/identity/security_level"];
    
    static async Task Main()
    {
        using var httpClient = new HttpClient();
        var discoveryDocument = await httpClient.GetDiscoveryDocumentAsync(AuthorityUrl);

        var dpopProofCreator = new DPoPProofCreator(new SecurityKey(JwkPrivateKey, "PS256"));

        var options = new OidcClientOptions
        {
            Authority = AuthorityUrl,
            ClientId = ClientId,
            RedirectUri = RedirectUri,
            LoadProfile = false,
            IdentityTokenValidator = new JwtHandlerIdentityTokenValidator()
        };
        options.ConfigureDPoP(JwkPrivateKey);
        var oidcClient = new OidcClient(options);

        var authorizeState = await oidcClient.PrepareLoginAsync();
        
        var clientAssertion = new ClientAssertion
        {
            Type = OidcConstants.ClientAssertionTypes.JwtBearer,
            Value = BuildClientAssertion(ClientId, discoveryDocument.Issuer!, CreateSigningCredentials(JwkPrivateKey)),
        };
        
        var pushedAuthorizationResponse = await httpClient.GetPushedAuthorizationResponseAsync(
            discoveryDocument.PushedAuthorizationRequestEndpoint!,
            ClientId,
            RedirectUri,
            clientAssertion,
            authorizeState,
            resources: [ApiResource1, ApiResource2],
            scopes: AllScopes);
        
        if (pushedAuthorizationResponse.IsError)
        {
            throw new Exception($"{pushedAuthorizationResponse.Error}: JSON: {pushedAuthorizationResponse.Json}");
        }
        
        var authorizeUrl = $"{discoveryDocument.AuthorizeEndpoint}?client_id={ClientId}&request_uri={pushedAuthorizationResponse.RequestUri}";
        var browserOptions = new BrowserOptions(authorizeUrl, RedirectUri);
        var browser = new SystemBrowser(port: LocalhostPort);
        var browserResult = await browser.InvokeAsync(browserOptions, default);
        
        var parameters = new Parameters
        {
            {"resource", ApiResource1}
        };

        oidcClient.Options.ClientAssertion = new ClientAssertion
        {
            Type = OidcConstants.ClientAssertionTypes.JwtBearer,
            Value = BuildClientAssertion(ClientId, discoveryDocument.Issuer!, CreateSigningCredentials(JwkPrivateKey)),
        };
        var loginResult = await oidcClient.ProcessResponseAsync(browserResult.Response, authorizeState, parameters);
        if (!loginResult.IsError)
        {
            loginResult = loginResult.ValidateIdentityClaims();
        }
        
        if (loginResult.IsError)
        {
            throw new Exception($"{loginResult.Error}: Description: {loginResult.ErrorDescription}");
        }
        
        var accessToken1 = loginResult.AccessToken;
        var refreshToken = loginResult.RefreshToken;

        Console.WriteLine("First request, resource: " + ApiResource1);
        Console.WriteLine("Access Token: " + accessToken1);
        Console.WriteLine("Refresh Token: " + refreshToken);
        Console.WriteLine();
        
        // Get AccessToken for ApiResource2
        oidcClient.Options.ClientAssertion = new ClientAssertion
        {
            Type = OidcConstants.ClientAssertionTypes.JwtBearer,
            Value = BuildClientAssertion(ClientId, discoveryDocument.Issuer!, CreateSigningCredentials(JwkPrivateKey)),
        };
        parameters = new Parameters
        {
            {"resource", ApiResource2}
        };
        
        var refreshTokenResult = await oidcClient.RefreshTokenAsync(refreshToken, parameters);

        if (refreshTokenResult.IsError)
        {
            throw new Exception($"{refreshTokenResult.Error}: Description: {refreshTokenResult.ErrorDescription}");
        }

        Console.WriteLine("Second request, resource: " + ApiResource2);
        Console.WriteLine("Access Token: " + refreshTokenResult.AccessToken);
        Console.WriteLine("Refresh Token: " + refreshTokenResult.RefreshToken);
        Console.WriteLine();
        
        
        // Call Patient Health Records API
        // /pingauth
        oidcClient.Options.ClientAssertion = new ClientAssertion
        {
            Type = OidcConstants.ClientAssertionTypes.JwtBearer,
            Value = BuildClientAssertion(ClientId, discoveryDocument.Issuer!, CreateSigningCredentials(JwkPrivateKey), GenerateAttestation("994598759", "994598759"))
        };
        parameters = new Parameters
        {
            { "resource", ApiResource2 }
        };
        refreshTokenResult = await oidcClient.RefreshTokenAsync(refreshTokenResult.RefreshToken, parameters);
        
        //Console.WriteLine(refreshTokenResult.AccessToken);
        
        //_ = await CallPhrPingAuth(httpClient, dpopProofCreator, refreshTokenResult.AccessToken);

        //var response = await CallPhrDocumentSearch(httpClient, dpopProofCreator, refreshTokenResult.AccessToken);

        var response = await CallPhrGetDocument(httpClient, dpopProofCreator, refreshTokenResult.AccessToken);
        
        Console.WriteLine(response.StatusCode);
        Console.WriteLine(await response.Content.ReadAsStringAsync());

        var logoutResult = await oidcClient.LogoutAsync(new LogoutRequest { IdTokenHint = loginResult.IdentityToken });
        //Console.WriteLine(logoutResult.Response);
    }

    private static string PjdBaseUrl = "https://api.pjd.test.nhn.no";
    private static async Task<HttpResponseMessage> CallPhrPingAuth(HttpClient httpClient, DPoPProofCreator proofCreator, string accessToken)
    {
        var proof = proofCreator.CreateDPoPProof($"{PjdBaseUrl}/pingauth", "GET", accessToken: accessToken);
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        httpClient.DefaultRequestHeaders.Add("DPoP", proof);
        var response = await httpClient.GetAsync($"{PjdBaseUrl}/pingauth");
        Console.WriteLine(response.StatusCode);
        return response;
    }

    private static async Task<HttpResponseMessage> CallPhrDocumentSearch(HttpClient httpClient,
        DPoPProofCreator proofCreator, string accessToken)
    {
        var proof = proofCreator.CreateDPoPProof($"{PjdBaseUrl}/R4/fhir/DocumentReference/_search", "POST", accessToken: accessToken);
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        httpClient.DefaultRequestHeaders.Add("DPoP", proof);
        // httpClient.DefaultRequestHeaders.Add("Accept", "application/fhir+json; fhirVersion=4.0");
        httpClient.DefaultRequestHeaders.Add("Content", "application/x-www-form-urlencoded");
        var urlencodedContent = new FormUrlEncodedContent([
            new("patient.identifier", "13116900216"),
            new("status", "current")
        ]);
        Console.WriteLine(await urlencodedContent.ReadAsStringAsync());
        return await httpClient.PostAsync($"{PjdBaseUrl}/R4/fhir/DocumentReference/_search",
            urlencodedContent);
    }
    
    private static async Task<HttpResponseMessage> CallPhrGetDocument(HttpClient httpClient,
        DPoPProofCreator proofCreator, string accessToken)
    {
        var proof = proofCreator.CreateDPoPProof($"https://api.pjd.test.nhn.no/mhd/iti68/document", "GET", accessToken: accessToken);
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        httpClient.DefaultRequestHeaders.Add("DPoP", proof);
        return await httpClient.GetAsync("https://api.pjd.test.nhn.no/mhd/iti68/document?documentUniqueId=928a2672-1604-43d5-8fcf-4bb2ae62e890&repositoryUniqueId=2.16.578.1.12.4.6.1.2&homeCommunityId=urn:oid:2.16.578.1.12.4.6.1.2");
    }
    
    private static string GenerateAttestation(string legalEntity, string pointOfCare)
    {
        return $$"""
            {
                "type": "nhn:tillitsrammeverk:parameters",
                    "practitioner": {
                        "authorization": {
                        "code": "LE",
                        "system": "urn:oid:2.16.578.1.12.4.1.1.9060"
                    },
                    "legal_entity": {
                        "id": "{{legalEntity}}",
                        "system": "urn:oid:2.16.578.1.12.4.1.4.101"
                    },
                    "point_of_care": {
                        "id": "{{pointOfCare}}",
                        "system": "urn:oid:2.16.578.1.12.4.1.4.101"
                    }
                },
                "care_relationship": {
                    "purpose_of_use": {
                      "code": "TREAT",
                      "system": "urn:oid:2.16.840.1.113883.1.11.20448"
                    },
                    "healthcare_service": {
                        "code": "S03",
                        "system": "urn:oid:2.16.578.1.12.4.1.1.8655"
                    },
                    "decision_ref": {
                        "id": "30F4AB40-DBC2-41A7-8AC4-181AD3FDC25B",
                        "user_selected": true
                    }
                },
                "patients": [{}]
            }
            """;
    }

    private static string GenerateHelseIdAuthorizationForSingleTenant(string organizationNumber)
    {
        return $$"""
             {
                 "type":"helseid_authorization",
                 "practitioner_role": {
                     "organization": {
                         "identifier": {
                             "system":"urn:oid:2.16.578.1.12.4.1.4.101",
                             "type":"ENH",
                             "value":"{{organizationNumber}}",
                         }
                     }
                 }
             }
             """;
    }
    
    private static SigningCredentials CreateSigningCredentials(string jwkPrivateKey)
    {
        var securityKey = new JsonWebKey(jwkPrivateKey);
        return new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
    }
    
    private static string BuildClientAssertion(string issuer, string audience, SigningCredentials signingCredentials, string? structuredClaim = null, string structuredClaimType = "assertion_details")
    {
        var claims = new List<Claim>
        {
            new(JwtClaimTypes.Subject, ClientId),
            new(JwtClaimTypes.IssuedAt, DateTimeOffset.Now.ToUnixTimeSeconds().ToString()),
            new(JwtClaimTypes.JwtId, Guid.NewGuid().ToString("N")),
        };
        if (!string.IsNullOrWhiteSpace(structuredClaim))
        {
            claims.Add(new Claim(structuredClaimType, structuredClaim, "json"));
        }
        
        var credentials = new JwtSecurityToken(
            issuer,
            audience,
            claims,
            DateTime.UtcNow,
            DateTime.UtcNow.AddSeconds(30),
            signingCredentials);

        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(credentials);
    }
}