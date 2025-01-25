using SelvbetjeningConsoleDemo.Auth.Utils;
using Spectre.Console;
using Spectre.Console.Json;
using Spectre.Console.Rendering;

namespace SelvbetjeningConsoleDemo;

public class JwtPrinter
{
    public static void PrintJwt(string jwt)
    {
        var payload = JwtDecoder.Decode(jwt);
        PrintBorderedContent(CreateRenderableJsonText(payload));
    }

    private static void PrintBorderedContent(IRenderable content, string? header = null)
    {
        var panel = new Panel(content)
            .Collapse()
            .RoundedBorder()
            .BorderColor(Color.Yellow);
        if (header != null)
        {
            panel.Header(header);
        }

        AnsiConsole.Write(panel);
    }

    private static JsonText CreateRenderableJsonText(string json)
    {
        return new JsonText(json)
            .MemberColor(Color.Aqua)
            .StringColor(Color.HotPink)
            .NumberColor(Color.MediumOrchid);
    }
}