using System.Text;
using System.Text.Json;

namespace SelvbetjeningConsoleDemo;

public record ClientConfig(string ClientId, string ClientJwk)
{
    public void Save()
    {
        var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true };
        var json = JsonSerializer.Serialize(this, jsonOptions);

        if (!Directory.Exists("Secrets"))
        {
            Directory.CreateDirectory("Secrets");
        }

        // This is an example and should NOT be used in production.
        // The key must be saved to a secure location, such as a key vault.
        File.WriteAllText("Secrets/client.json", json, Encoding.UTF8);
    }

    public static ClientConfig? Load()
    {
        if (!File.Exists("Secrets/client.json"))
        {
            return null;
        }

        // This is an example and should NOT be used in production.
        // The key must be saved to a secure location, such as a key vault.
        var configText = File.ReadAllText("Secrets/client.json", Encoding.UTF8);
        var config = JsonSerializer.Deserialize<ClientConfig>(configText);

        return config;
    }
}