namespace SimpleSign.Integration.Tests.Helpers;

/// <summary>
/// Resolves paths to test fixture PDFs.
/// </summary>
internal static class FixturePath
{
    private const string Dir = "Fixtures";

    public static string Get(string fileName) => Path.Combine(Dir, fileName);

    public static bool Exists(string fileName) => File.Exists(Get(fileName));

    public static Stream Open(string fileName) =>
        new FileStream(Get(fileName), FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);

    public static Task<byte[]> ReadBytesAsync(string fileName)
        => File.ReadAllBytesAsync(Get(fileName));
}
