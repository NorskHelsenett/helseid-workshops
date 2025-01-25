using Microsoft.IdentityModel.Tokens;

namespace SelvbetjeningConsoleDemo.Models;

public class JwkWithMetadata
{
    public string PublicAndPrivateValue { get; }
    public string PublicValue { get; }
    public string Algorithm { get; }
    public string Kid { get; }

    public JwkWithMetadata(string publicAndPrivateValue, string publicValue = "")
    {
        PublicAndPrivateValue = publicAndPrivateValue;
        PublicValue = publicValue;

        Algorithm = new JsonWebKey(publicAndPrivateValue).Alg;
        Kid = new JsonWebKey(publicAndPrivateValue).Kid;
        if (string.IsNullOrWhiteSpace(Algorithm))
        {
            throw new Exception("JWK must include the 'alg' parameter");
        }
    }
}