using System.Text;
using System.Text.Json;

namespace SelvbetjeningConsoleDemo;

public record ClientConfig(string ClientId, string ClientJwk)
{
    private const string ConfigPath = "Secrets/client.json";
    // private const string ConfigPath = "Secrets/client.mt.json";

    public void Save()
    {
        var jsonOptions = new JsonSerializerOptions(JsonDefaults.JsonSerializerOptions) { WriteIndented = true };
        var json = JsonSerializer.Serialize(this, jsonOptions);

        var dirName = Path.GetDirectoryName(ConfigPath)!;
        if (!Directory.Exists(dirName))
        {
            Directory.CreateDirectory(dirName);
        }

        // This is an example and should NOT be used in production.
        // The key must be saved to a secure location, such as a key vault.
        File.WriteAllText(ConfigPath, json, Encoding.UTF8);
    }

    public static ClientConfig? Load()
    {
        if (!File.Exists(ConfigPath))
        {
            return null;
        }

        // This is an example and should NOT be used in production.
        // The key must be saved to a secure location, such as a key vault.
        var configText = File.ReadAllText(ConfigPath, Encoding.UTF8);
        var config = JsonSerializer.Deserialize<ClientConfig>(configText, JsonDefaults.JsonSerializerOptions);

        return config;
    }
}