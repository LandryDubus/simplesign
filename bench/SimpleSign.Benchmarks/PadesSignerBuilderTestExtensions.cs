using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.Benchmarks;

/// <summary>Constructs complete field options from concise benchmark fixture data.</summary>
internal static class PadesSignerBuilderTestExtensions
{
    internal static PadesSignerBuilder WithTestFieldOptions(this PadesSignerBuilder builder,
        string? signerName = null, string? reason = null, string? location = null) =>
        builder.WithFieldOptions(new SignatureFieldOptions
        {
            SignerName = signerName,
            Reason = reason,
            Location = location
        });
}
