namespace SelvbetjeningConsoleDemo.Models.Response;

public class MultiTenantDelegation
{
    public required Delegator Delegator { get; set; }

    public ServiceTerms[] ServiceTerms { get; set; } = [];
}

public class ServiceTerms
{
    public string Uri { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public bool DelegatorHasSigned { get; set; }
    public string[] Scopes { get; set; } = [];
}

public class Delegator
{
    public required string OrganizationNumber { get; set; }
    public string Name { get; set; } = string.Empty;
    public bool IsHelsenettMember { get; set; }
}
