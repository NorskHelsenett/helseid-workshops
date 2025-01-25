using System.Text.Json;
using IdentityModel.OidcClient.Browser;
using Microsoft.Extensions.Configuration;
using SelvbetjeningConsoleDemo;
using SelvbetjeningConsoleDemo.Auth;
using SelvbetjeningConsoleDemo.Auth.Utils;
using SelvbetjeningConsoleDemo.Crypto;
using SelvbetjeningConsoleDemo.Models;
using SelvbetjeningConsoleDemo.Models.Response;
using Spectre.Console;
using Spectre.Console.Json;

const string selvbetjeningResource = "nhn:selvbetjening";

var running = true;
while (running)
{
    running = await PromptForAction();
}

return;

static async Task<bool> PromptForAction()
{
    var config = GetAppConfig();
    var clientConfig = ClientConfig.Load();

    if (clientConfig == null)
    {
        AnsiConsole.WriteLine("HelseID client not configured");
    }
    else
    {
        var jwk = new JwkWithMetadata(clientConfig.ClientJwk);
        AnsiConsole.WriteLine($"HelseID client id: {clientConfig.ClientId}");
        AnsiConsole.WriteLine($"HelseID client key id: {jwk.Kid}");
    }

    var choices = new List<string>();

    if (clientConfig == null)
    {
        choices.Add("Create client");
    }
    else
    {
        choices.Add("Log in with HelseID");
        choices.Add("Check client status");
        choices.Add("Renew client key");
        choices.Add("Add scope");
    }

    choices.Add("Exit");

    var action = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("What do you want to do?")
            .AddChoices(choices));
    switch (action)
    {
        case "Create client":
            await AnsiConsole.Status()
                .StartAsync("Starting client creation...", async ctx => await CreateClient(config, ctx));
            break;
        case "Log in with HelseID":
            await AnsiConsole.Status()
                .StartAsync("Starting login...", async ctx => await Login(config, clientConfig!, ctx));
            break;
        case "Add scope":
            var scope = AnsiConsole.Prompt(new TextPrompt<string>("Enter the scope to add:")).Trim();
            await AnsiConsole.Status()
                .StartAsync("Adding scope...", async ctx => await AddScope(scope, config, clientConfig!, ctx));
            break;
        case "Check client status":
            await AnsiConsole.Status()
                .StartAsync("Adding scope...", async ctx => await CheckClientStatus(config, clientConfig!, ctx));
            break;
        case "Renew client key":
            await AnsiConsole.Status()
                .StartAsync("Renewing key...", async ctx => await RotateClientKey(config, clientConfig!, ctx));
            break;
        default:
            return false;
    }

    return true;
}

static async Task CreateClient(Config config, StatusContext statusContext)
{
    statusContext.Status("Creating client draft...");

    var jwk = KeyGenerator.GenerateRsaJwk();
    AnsiConsole.MarkupLine($"Generated JWK with KID: {jwk.Kid}");

    var redirectUri = $"http://localhost:{config.LocalHttpServer.RedirectPort}";
    var redirectPath = $"/{config.LocalHttpServer.RedirectPath}";
    using var authHttpClient = new AuthHttpClient(jwk);

    var clientId = (await SubmitClientDraft(config, jwk.PublicValue, authHttpClient)).ClientId;
    AnsiConsole.MarkupLine($"Created client draft with client ID: {clientId}");

    new ClientConfig(clientId, jwk.PublicAndPrivateValue).Save();

    statusContext.Status("Waiting for user confirmation...");

    var confirmationStatus = await ConfirmClientDraft(config, clientId, redirectUri, redirectPath);
    AnsiConsole.MarkupLine($"Status retrieved: {confirmationStatus}");

    if (confirmationStatus != "Success")
    {
        Console.WriteLine($"Confirmation status is {confirmationStatus}. Aborting ...");
        return;
    }

    AnsiConsole.MarkupLine("Client confirmed");

    statusContext.Status($"Waiting for HelseID cache to refresh...");
    await Task.Delay(TimeSpan.FromSeconds(10));

    statusContext.Status("Retrieving client details...");

    var clientDataForSelvbetjeningScopes = new SystemClientData
    {
        Authority = config.HelseId.Authority,
        ClientId = clientId,
        Jwk = jwk,
        Scopes = config.ClientDraft.ApiScopes.Where(s => s.StartsWith(selvbetjeningResource)).ToArray(),
    };

    var currentClient = await GetClientInfo(authHttpClient, clientDataForSelvbetjeningScopes,
        config.Selvbetjening.ClientUri);

    var accessOk = currentClient.ApiScopes.All(s => s.Status == ScopeAccessStatus.Ok) &&
                   currentClient.AudienceSpecificClientClaims.All(c => c.Status == AudienceSpecificClaimStatus.Ok);

    if (!accessOk)
    {
        Console.WriteLine("Client status is not OK. Aborting ...");
        return;
    }

    AnsiConsole.MarkupLine("Client is ready");

    PrintClientDetails(currentClient);
}

static async Task Login(Config config, ClientConfig clientConfig, StatusContext statusContext)
{
    var clientData = new UserClientData
    {
        ClientId = clientConfig.ClientId,
        Authority = config.HelseId.Authority,
        Jwk = new JwkWithMetadata(clientConfig.ClientJwk),
        RedirectHost = $"http://localhost:{config.LocalHttpServer.RedirectPort}",
        RedirectPath = $"/{config.LocalHttpServer.RedirectPath}",
        Resources = GetResources(config.ClientDraft.ApiScopes),
    };

    using var auth =
        new UserAuthenticator(clientData, config.LocalHttpServer.HtmlTitle, config.LocalHttpServer.HtmlBody);

    ResourceTokens initialResourceTokens;
    string idToken;
    try
    {
        statusContext.Status("Authenticating user and retrieving initial tokens...");
        (initialResourceTokens, idToken) = await auth.LoginAndGetTokens(resources: [selvbetjeningResource]);
    }
    catch (Exception ex)
    {
        AnsiConsole.MarkupLine($"Error getting initial token: {ex.Message}");
        return;
    }

    AnsiConsole.MarkupLine($"Retrieved access token for '{selvbetjeningResource}' and refresh token");
    JwtPrinter.PrintJwt(initialResourceTokens.Tokens.Single().AccessToken);

    var refreshToken = initialResourceTokens.RefreshToken;
    var remainingResources = clientData.Resources.Where(cr => cr.Name != selvbetjeningResource);

    foreach (var resource in remainingResources.Select(r => r.Name))
    {
        ResourceTokens resourceTokens;
        try
        {
            statusContext.Status($"Retrieving tokens for '{resource}'...");
            resourceTokens = await auth.GetTokens(refreshToken, resource);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"Error getting token for resource '{resource}': {ex.Message}");
            return;
        }

        refreshToken = resourceTokens.RefreshToken;
        AnsiConsole.MarkupLine($"Retrieved access token for '{resource}' and new refresh token");
        JwtPrinter.PrintJwt(resourceTokens.Tokens.Single().AccessToken);
    }

    var idTokenPayload = JsonDocument.Parse(JwtDecoder.Decode(idToken));
    var name = idTokenPayload.RootElement.GetProperty("name").GetString();
    AnsiConsole.MarkupLine($"Logged in as {name}");
}

static async Task AddScope(string scope, Config config, ClientConfig clientConfig, StatusContext statusContext)
{
    var clientData = new SystemClientData
    {
        Authority = config.HelseId.Authority,
        ClientId = clientConfig.ClientId,
        Jwk = new JwkWithMetadata(clientConfig.ClientJwk),
        Scopes = config.ClientDraft.ApiScopes.Where(s => s.StartsWith(selvbetjeningResource)).ToArray(),
    };

    statusContext.Status("Getting access token...");
    var accessToken = await GetClientCredentialsAccessToken(clientData);

    using var authHttpClient = new AuthHttpClient(clientData.Jwk);

    statusContext.Status("Getting client info...");

    var clientInfo = await authHttpClient.Get<CurrentClient>(config.Selvbetjening.ClientUri, accessToken: accessToken);

    AnsiConsole.WriteLine($"Current scopes: [{string.Join(", ", clientInfo.ApiScopes.Select(s => s.Scope))}]");

    if (clientInfo.ApiScopes.Any(s => s.Scope == scope))
    {
        AnsiConsole.WriteLine($"Client already has scope '{scope}'. Skipping update.");
    }

    var clientUpdate = clientInfo.ToClientUpdate();
    clientUpdate.ApiScopes.Add(scope);

    statusContext.Status("Updating client...");

    await authHttpClient.Put(config.Selvbetjening.ClientUri, clientUpdate, accessToken: accessToken);

    AnsiConsole.WriteLine($"New scopes: [{string.Join(", ", clientUpdate.ApiScopes)}]");
}

static async Task RotateClientKey(Config config, ClientConfig clientConfig, StatusContext statusContext)
{
    var clientData = new SystemClientData
    {
        Authority = config.HelseId.Authority,
        ClientId = clientConfig.ClientId,
        Jwk = new JwkWithMetadata(clientConfig.ClientJwk),
        Scopes = config.ClientDraft.ApiScopes.Where(s => s.StartsWith(selvbetjeningResource)).ToArray(),
    };

    statusContext.Status("Getting access token...");
    var accessToken = await GetClientCredentialsAccessToken(clientData);

    using var authHttpClient = new AuthHttpClient(clientData.Jwk);

    var jwk = KeyGenerator.GenerateRsaJwk();
    AnsiConsole.MarkupLine($"Generated JWK with KID: {jwk.Kid}");

    statusContext.Status("Adding new client key...");

    var response = await authHttpClient.Post<string, ClientSecretUpdateResponse>(config.Selvbetjening.ClientSecretUri,
        jwk.PublicValue, accessToken: accessToken);

    AnsiConsole.WriteLine($"New key expires at {response.Expiration}");

    clientConfig = clientConfig with { ClientJwk = jwk.PublicAndPrivateValue };
    clientConfig.Save();
}

static async Task CheckClientStatus(Config config, ClientConfig clientConfig, StatusContext statusContext)
{
    var clientData = new SystemClientData
    {
        Authority = config.HelseId.Authority,
        ClientId = clientConfig.ClientId,
        Jwk = new JwkWithMetadata(clientConfig.ClientJwk),
        Scopes = config.ClientDraft.ApiScopes.Where(s => s.StartsWith(selvbetjeningResource)).ToArray(),
    };

    statusContext.Status("Getting access token...");
    var accessToken = await GetClientCredentialsAccessToken(clientData);

    using var authHttpClient = new AuthHttpClient(clientData.Jwk);

    statusContext.Status("Getting client info...");

    var clientInfo = await authHttpClient.Get<CurrentClient>(config.Selvbetjening.ClientUri, accessToken: accessToken);
    PrintClientDetails(clientInfo);
}

static async Task<ClientDraftResponse> SubmitClientDraft(Config config, string publicJwk, AuthHttpClient authHttpClient)
{
    var clientDraft = new ClientDraft(config.ClientDraft.OrganizationNumber, publicJwk, config.ClientDraft.ApiScopes)
    {
        AudienceSpecificClientClaims = config.ClientDraft.AudienceSpecificClientClaims,
        ChildOrganizationNumbers = config.ClientDraft.ChildOrganizationNumbers,
        RedirectUris = config.ClientDraft.RedirectUris,
    };

    return await authHttpClient.Post<ClientDraft, ClientDraftResponse>(
        config.Selvbetjening.ClientDraftUri, clientDraft,
        headers: new Dictionary<string, string>
            { [config.Selvbetjening.ClientDraftApiKeyHeader] = config.Selvbetjening.ClientDraftApiKey });
}

static async Task<string> ConfirmClientDraft(Config config, string clientId, string redirectUri, string redirectPath)
{
    var confirmationUri = config.Selvbetjening.ConfirmationUri.Replace("<client_id>", clientId)
        .Replace("<port>", config.LocalHttpServer.RedirectPort.ToString()).Replace("<path>", redirectPath);

    var browserOptions = new BrowserOptions(confirmationUri,
        new Uri(new Uri(redirectUri), config.LocalHttpServer.RedirectPath).ToString());

    using var browserRunner =
        new SystemBrowserRunner(config.LocalHttpServer.HtmlTitle, config.LocalHttpServer.HtmlBody);
    var result = await browserRunner.InvokeAsync(browserOptions, default);

    var confirmationDict = QuerystringToDictionary(result.Response);

    var confirmationStatus = confirmationDict["status"];

    return confirmationStatus;
}

static Dictionary<string, string> QuerystringToDictionary(string confirmationResult)
{
    return confirmationResult[1..].Split("&").Select(s => s.Split("=")).ToDictionary(s => s[0], s => s[1]);
}

static async Task<CurrentClient> GetClientInfo(AuthHttpClient authHttpClient, SystemClientData clientData,
    string clientStatusUri)
{
    var accessToken = await GetClientCredentialsAccessToken(clientData);

    var response =
        await authHttpClient.Get<CurrentClient>(clientStatusUri, accessToken: accessToken);

    return response;
}

static async Task<string> GetClientCredentialsAccessToken(SystemClientData clientData)
{
    using var auth = new SystemAuthenticator(clientData);

    var tokens = await auth.GetTokens();
    return tokens.AccessToken;
}

static Resource[] GetResources(string[] apiScopes)
{
    var dict = new Dictionary<string, List<string>>();

    foreach (var scope in apiScopes)
    {
        var parts = scope.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var resourceName = parts[0];

        if (!dict.TryGetValue(resourceName, out var scopeList))
        {
            scopeList = new List<string>();
            dict.Add(resourceName, scopeList);
        }

        scopeList.Add(scope);
    }

    return dict.Select(kvp => new Resource(kvp.Key, kvp.Value.ToArray())).ToArray();
}

static void PrintClientDetails(CurrentClient clientInfo)
{
    var currentClientJson =
        JsonSerializer.Serialize(clientInfo, JsonDefaults.JsonSerializerOptions);
    AnsiConsole.Write(
        new Panel(new JsonText(currentClientJson))
            .Header("Client Details")
            .Collapse()
            .RoundedBorder()
            .BorderColor(Color.Yellow));
}

static Config GetAppConfig()
{
    var builder = new ConfigurationBuilder()
        .SetBasePath(Directory.GetCurrentDirectory())
        .AddJsonFile("appsettings.json", optional: false)
        .AddJsonFile("appsettings.Local.json", optional: true);

    IConfiguration configuration = builder.Build();

    var config = configuration.Get<Config>();

    if (config == null)
    {
        throw new Exception("Config is null.");
    }

    return config;
}