using RevenantHardening.Core.Models;

namespace RevenantHardening.Core;

public static class FileWalker
{
    private static readonly HashSet<string> DefaultExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".xaml", ".resx", ".csproj", ".props", ".targets",
        ".config", ".json", ".xml", ".appxmanifest"
    };

    private static readonly HashSet<string> DefaultExcludeSegments = new(StringComparer.OrdinalIgnoreCase)
    {
        "bin", "obj", ".git", ".vs", ".idea", "packages", "node_modules"
    };

    public static IEnumerable<FileContext> Enumerate(
        string root,
        string[]? extraIncludes = null,
        string[]? extraExcludes = null)
    {
        var excludeSegments = new HashSet<string>(DefaultExcludeSegments, StringComparer.OrdinalIgnoreCase);
        if (extraExcludes != null)
            foreach (var e in extraExcludes)
                excludeSegments.Add(e);

        var includeExtensions = new HashSet<string>(DefaultExtensions, StringComparer.OrdinalIgnoreCase);
        if (extraIncludes != null)
            foreach (var i in extraIncludes)
                includeExtensions.Add(i);

        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            if (IsExcluded(file, root, excludeSegments))
                continue;

            var ext = System.IO.Path.GetExtension(file);
            if (!includeExtensions.Contains(ext))
                continue;

            string content;
            try
            {
                content = File.ReadAllText(file);
            }
            catch
            {
                continue;
            }

            var relative = System.IO.Path.GetRelativePath(root, file);
            yield return new FileContext(file, relative, content);
        }
    }

    private static bool IsExcluded(string filePath, string root, HashSet<string> excludeSegments)
    {
        var relative = System.IO.Path.GetRelativePath(root, filePath);
        var parts = relative.Split(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar);
        foreach (var part in parts)
        {
            if (excludeSegments.Contains(part))
                return true;
        }
        return false;
    }
}
