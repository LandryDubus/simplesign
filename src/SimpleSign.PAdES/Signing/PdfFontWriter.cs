using System.Text;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Writes PDF font streaming infrastructure for embedded TrueType fonts.
/// Generates the font file stream object (FontFile2) and font descriptor
/// object required by PDF/A-1 (ISO 19005-1 §6.3.4).
/// </summary>
internal static class PdfFontWriter
{
    /// <summary>
    /// Builds a font file stream object (/FontFile2) containing the LiberationSans
    /// TTF data compressed with FlateDecode.
    /// </summary>
    internal static byte[] BuildFontFileObject(int objNum)
    {
        var compressed = FontResources.CompressedTtf;
        var sb = new StringBuilder();
        sb.Append($"{objNum} 0 obj\n");
        sb.Append("<< /Length ");
        sb.Append(compressed.Length);
        sb.Append("\n   /Filter /FlateDecode\n");
        sb.Append(">>\nstream\n");

        var header = Encoding.Latin1.GetBytes(sb.ToString());
        var trailer = Encoding.Latin1.GetBytes("\nendstream\nendobj\n");

        var result = new byte[header.Length + compressed.Length + trailer.Length];
        header.CopyTo(result, 0);
        compressed.CopyTo(result, header.Length);
        trailer.CopyTo(result, header.Length + compressed.Length);
        return result;
    }

    /// <summary>
    /// Builds a font descriptor object referencing the font file stream.
    /// Metrics match the LiberationSans (WinAnsi subset) font program.
    /// </summary>
    internal static byte[] BuildFontDescriptorObject(int objNum, int fontFileObjNum)
    {
        var bbox = FontResources.FontBBox;
        var sb = new StringBuilder();
        sb.Append($"{objNum} 0 obj\n");
        sb.Append("<< /Type /FontDescriptor\n");
        sb.Append($"   /FontName /LiberationSans\n");
        sb.Append($"   /Flags {FontResources.Flags}\n");
        sb.Append($"   /FontBBox [{bbox[0]} {bbox[1]} {bbox[2]} {bbox[3]}]\n");
        sb.Append($"   /ItalicAngle {FontResources.ItalicAngle}\n");
        sb.Append($"   /Ascent {FontResources.Ascent}\n");
        sb.Append($"   /Descent {FontResources.Descent}\n");
        sb.Append($"   /CapHeight {FontResources.CapHeight}\n");
        sb.Append($"   /StemV {FontResources.StemV}\n");
        sb.Append($"   /FontFile2 {fontFileObjNum} 0 R\n");
        sb.Append(">>\nendobj\n");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    /// <summary>
    /// Builds the /Widths array string for the font dictionary.
    /// </summary>
    internal static string BuildWidthsArray()
    {
        var sb = new StringBuilder();
        sb.Append("/Widths [");
        var widths = FontResources.Widths;
        for (int i = 0; i < widths.Length; i++)
        {
            if (i > 0)
            {
                sb.Append(' ');
            }
            sb.Append(widths[i]);
        }
        sb.Append(']');
        return sb.ToString();
    }
}
