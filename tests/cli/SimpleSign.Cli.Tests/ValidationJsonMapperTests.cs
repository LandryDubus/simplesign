using Shouldly;
using SimpleSign.Cli.Json;
using SimpleSign.Core.Validation;

namespace SimpleSign.Cli.Tests;

public sealed class ValidationJsonMapperTests
{
    [Theory]
    [InlineData(RevocationSource.Indeterminate, true, null)]
    [InlineData(RevocationSource.None, true, null)]
    [InlineData(RevocationSource.OnlineOcsp, true, false)]
    [InlineData(RevocationSource.EmbeddedCrl, false, true)]
    public void MapValidation_RevocationStatus_DistinguishesUnknownFromConfirmed(
        RevocationSource source, bool isNotRevoked, bool? expectedRevoked)
    {
        var result = new SignatureValidationResult
        {
            FieldName = "Signature1",
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = true,
            IsNotRevoked = isNotRevoked,
            RevocationSource = source,
            Warnings = source == RevocationSource.Indeterminate ? ["Revocation check timed out."] : []
        };

        var output = JsonMapper.MapValidation("signed.pdf", [result]);
        var signature = output.Signatures.ShouldHaveSingleItem();

        signature.Valid.ShouldBe(result.IsValid);
        signature.Revoked.ShouldBe(expectedRevoked);
        signature.RevocationSource.ShouldBe(source.ToString());
        signature.Warnings.ShouldBe(result.Warnings);
    }
}
