using iText.Kernel.Geom;
using iText.Kernel.Pdf;

namespace SimpleSign.Benchmarks;

internal static class PdfHelper
{
    public static byte[] BuildMinimalPdf()
    {
        using var ms = new MemoryStream();
        using (var writer = new PdfWriter(ms))
        using (var doc = new PdfDocument(writer))
        {
            doc.AddNewPage(PageSize.A4);
        }

        return ms.ToArray();
    }

    public static byte[] BuildPdfWithPages(int pageCount)
    {
        using var ms = new MemoryStream();
        using (var writer = new PdfWriter(ms))
        using (var doc = new PdfDocument(writer))
        {
            for (int i = 0; i < pageCount; i++)
            {
                doc.AddNewPage(PageSize.A4);
            }
        }

        return ms.ToArray();
    }
}
