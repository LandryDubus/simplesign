namespace SimpleSign.Core.Signing;

/// <summary>
/// Test-only payload callback implementation used by signing tests that do not
/// need to inspect the complete external-signing request.
/// </summary>
/// <remarks>
/// Production integrations must implement <see cref="IExternalSigner"/> directly
/// so that algorithm, payload-kind, operation, and PSS-parameter information is
/// available to the signing device.
/// </remarks>
public sealed class DelegatingExternalSigner : IExternalSigner
{
    private readonly Func<byte[], Task<byte[]>> _callback;

    /// <summary>Creates a test signer from a callback over the payload bytes.</summary>
    /// <param name="callback">Callback that produces raw signature bytes.</param>
    public DelegatingExternalSigner(Func<byte[], Task<byte[]>> callback)
    {
        ArgumentNullException.ThrowIfNull(callback);
        _callback = callback;
    }

    /// <inheritdoc />
    public async ValueTask<ReadOnlyMemory<byte>> SignAsync(
        ExternalSigningRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await _callback(request.DataToSign.ToArray()).ConfigureAwait(false);
    }
}
