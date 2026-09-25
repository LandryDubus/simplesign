using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;

namespace SimpleSign.Integration.Tests;

internal static class OfflinePdfValidator
{
    private static readonly HttpClient HttpClient = MockHttpHandler.Failing();

    internal static PdfSignatureValidator Create() =>
        new(new ValidationOptions { CheckRevocation = false }, HttpClient);
}
