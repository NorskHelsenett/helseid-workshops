using System.Text.Json;
using System.Text.Json.Serialization;

namespace SelvbetjeningConsoleDemo;

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions JsonSerializerOptions = new(JsonSerializerDefaults.Web);

    static JsonDefaults()
    {
        JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    }
}