namespace SelvbetjeningConsoleDemo.Models
{
    public class ClientUpdate
    {
        public required List<string> ApiScopes { get; set; } = [];
        public required AudienceSpecificClientClaim[]? AudienceSpecificClientClaims { get; set; }
        public required List<string>? RedirectUris { get; set; }
        public required List<string>? PostLogoutRedirectUris { get; set; }
        public required List<string>? ChildOrganizationNumbers { get; set; }
    }
}