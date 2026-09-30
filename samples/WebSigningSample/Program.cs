using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();

var app = builder.Build();
app.UseStaticFiles();
var deferredSessions = new ConcurrentDictionary<string, byte[]>();
byte[] sessionIntegrityKey = RandomNumberGenerator.GetBytes(32);

// POST /api/prepare — receives PDF files + certificate, returns hashes to sign
app.MapPost("/api/prepare", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    var certBase64 = form["certificateBase64"].ToString();

    if (string.IsNullOrEmpty(certBase64))
    {
        return Results.BadRequest(new { error = "certificateBase64 is required" });
    }

#if NET9_0_OR_GREATER
    using var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certBase64));
#else
    using var cert = new X509Certificate2(Convert.FromBase64String(certBase64));
#endif

    var files = form.Files;

    if (files.Count == 0)
    {
        return Results.BadRequest(new { error = "No PDF files provided" });
    }

    var preparedDocs = new List<object>();

    for (int i = 0; i < files.Count; i++)
    {
        var file = files[i];
        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        var pdfBytes = ms.ToArray();

        try
        {
            var reason = form["reason"].ToString();
            var location = form["location"].ToString();

            var fieldOptions = new SignatureFieldOptions
            {
                SignerName = cert.GetNameInfo(X509NameType.SimpleName, false) ?? "Signer",
                Reason = string.IsNullOrWhiteSpace(reason) ? null : reason,
                Location = string.IsNullOrWhiteSpace(location) ? null : location
            };
            var deferredBuilder = DeferredSigner.Document(pdfBytes)
                .WithCertificate(cert)
                .WithSessionIntegrityKey(sessionIntegrityKey)
                .WithFieldOptions(fieldOptions);

            var prepared = await deferredBuilder.PrepareAsync();
            string sessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            deferredSessions[sessionId] = prepared.SessionData;

            preparedDocs.Add(new
            {
                index = i,
                fileName = file.FileName,
                hashBase64 = Convert.ToBase64String(prepared.HashToSign),
                sessionId,
                digestAlgorithm = prepared.DigestAlgorithm,
                signatureAlgorithmOid = prepared.SignatureAlgorithmOid
            });
        }
        catch (Exception ex)
        {
            preparedDocs.Add(new
            {
                index = i,
                fileName = file.FileName,
                error = ex.Message
            });
        }
    }

    return Results.Ok(preparedDocs);
}).DisableAntiforgery();

// POST /api/complete — receives a server-side session ID + signature, returns signed PDF
app.MapPost("/api/complete", async (HttpRequest request) =>
{
    var body = await request.ReadFromJsonAsync<CompleteRequest>();
    if (body is null || string.IsNullOrEmpty(body.SessionId) || string.IsNullOrEmpty(body.SignedHashBase64))
    {
        return Results.BadRequest(new { error = "SessionId and SignedHashBase64 are required" });
    }

    try
    {
        if (!deferredSessions.TryRemove(body.SessionId, out byte[]? sessionData))
        {
            return Results.BadRequest(new { error = "Session not found or already completed" });
        }

        var signature = Convert.FromBase64String(body.SignedHashBase64);

        var signedPdf = await DeferredSigner.Resume(sessionData, sessionIntegrityKey).CompleteAsync(signature);

        return Results.Ok(new { signedPdfBase64 = Convert.ToBase64String(signedPdf) });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
}).DisableAntiforgery();

// Fallback to index.html
app.MapFallbackToFile("index.html");

app.Run();

public sealed class CompleteRequest
{
    public string SessionId { get; set; } = "";
    public string SignedHashBase64 { get; set; } = "";
}
