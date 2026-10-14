using System.Globalization;
using System.Text;
using SimpleSign.Pdf.Constants;

namespace SimpleSign.Pdf;

/// <summary>
/// Minimal PDF structure parser that locates objects, cross-references, page trees,
/// AcroForm dictionaries, and MediaBox dimensions by scanning raw PDF bytes.
/// Does not build a full object graph — only extracts what is needed for incremental signing.
/// </summary>
internal static class PdfStructureParser
{
    /// <summary>
    /// Determines the next available PDF object number by taking the maximum of the
    /// trailer <c>/Size</c> value and the highest object number found in the file, plus one.
    /// </summary>
    public static int DetermineNextObjectNumber(ReadOnlySpan<byte> pdfData) => Math.Max(FindTrailerSize(pdfData), FindHighestObjectNumber(pdfData) + 1);

    /// <summary>
    /// Reads the <c>/Root N 0 R</c> reference from the trailer to find the catalog object number.
    /// Falls back to 1 if the trailer cannot be parsed.
    /// </summary>
    public static int FindRootObjectNumber(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> rootToken = "/Root "u8;
        int tokenPos = data.LastIndexOf(rootToken);
        if (tokenPos < 0)
        {
            return 1;
        }

        int cursor = tokenPos + rootToken.Length;
        int rootObjNum = 0;
        while (cursor < data.Length && data[cursor] >= (byte)'0' && data[cursor] <= (byte)'9')
        {
            if (rootObjNum > int.MaxValue / 10)
            {
                return 1;
            }

            rootObjNum = rootObjNum * 10 + (data[cursor++] - '0');
        }

        return rootObjNum <= 0 ? 1 : rootObjNum;
    }

    /// <summary>
    /// Finds the byte boundaries of a PDF object (<c>N 0 obj ... endobj</c>) in the data.
    /// Returns the LAST occurrence (correct for incremental updates where later revisions override earlier ones).
    /// Returns (-1, -1) if not found.
    /// </summary>
    public static (int Start, int End) FindObjectBytes(ReadOnlySpan<byte> data, int objNum)
    {
        byte[] objHeader = Encoding.Latin1.GetBytes($"{objNum} 0 obj");
        int searchPos = 0;
        int lastMatchStart = -1;
        int lastMatchEnd = -1;

        while (searchPos < data.Length)
        {
            int matchPos = data.Slice(searchPos).IndexOf(objHeader);
            if (matchPos < 0)
            {
                break;
            }
            matchPos += searchPos;

            // Ensure this isn't a suffix match (e.g., "12 0 obj" matching inside "112 0 obj").
            if (matchPos > 0 && data[matchPos - 1] >= (byte)'0' && data[matchPos - 1] <= (byte)'9')
            {
                searchPos = matchPos + 1;
                continue;
            }

            // Ensure the token is followed by whitespace or '<<' (start of dictionary).
            int afterHeader = matchPos + objHeader.Length;
            if (afterHeader < data.Length
                && data[afterHeader] != (byte)'\n'
                && data[afterHeader] != (byte)'\r'
                && data[afterHeader] != (byte)' '
                && data[afterHeader] != (byte)'<')
            {
                searchPos = matchPos + 1;
                continue;
            }

            // Find the closing "endobj" marker.
            ReadOnlySpan<byte> endObjToken = "endobj"u8;
            int endObjRelative = data.Slice(matchPos).IndexOf(endObjToken);
            if (endObjRelative < 0)
            {
                break;
            }

            lastMatchStart = matchPos;
            lastMatchEnd = matchPos + endObjRelative + endObjToken.Length;
            searchPos = lastMatchEnd;
        }

        return (Start: lastMatchStart, End: lastMatchEnd);
    }

    /// <summary>
    /// Finds the AcroForm object number referenced by the catalog's <c>/AcroForm N 0 R</c> entry.
    /// Returns 0 if no AcroForm reference is found or if it's an inline dictionary.
    /// </summary>
    public static int FindAcroFormObjNum(ReadOnlySpan<byte> data, int catalogObjNum)
    {
        var (objStart, objEnd) = FindObjectBytes(data, catalogObjNum);
        if (objStart < 0)
        {
            return 0;
        }

        string catalogText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
        int acroFormKeyPos = catalogText.IndexOf(PdfKeys.AcroForm, StringComparison.Ordinal);
        if (acroFormKeyPos < 0)
        {
            return 0;
        }

        int cursor;
        for (cursor = acroFormKeyPos + PdfKeys.AcroForm.Length; cursor < catalogText.Length && (catalogText[cursor] == ' ' || catalogText[cursor] == '\n' || catalogText[cursor] == '\r'); cursor++)
        {
        }

        if (cursor < catalogText.Length && catalogText[cursor] != '<')
        {
            int acroFormObjNum = 0;
            while (cursor < catalogText.Length && char.IsDigit(catalogText[cursor]))
            {
                if (acroFormObjNum > int.MaxValue / 10)
                {
                    return 0;
                }

                acroFormObjNum = acroFormObjNum * 10 + (catalogText[cursor++] - '0');
            }
            return acroFormObjNum;
        }

        return 0;
    }

    /// <summary>
    /// Extracts /Fields references from an inline AcroForm dictionary in the Catalog.
    /// Used when the AcroForm is embedded directly (not an indirect reference).
    /// Returns an empty list if no inline AcroForm or /Fields is found.
    /// </summary>
    public static List<string> ExtractInlineAcroFormFields(ReadOnlySpan<byte> data, int catalogObjNum)
    {
        var (objStart, objEnd) = FindObjectBytes(data, catalogObjNum);
        if (objStart < 0)
        {
            return [];
        }

        string catalogText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
        var (dictStart, dictEnd) = FindInlineAcroFormBounds(catalogText);
        if (dictStart < 0)
        {
            return [];
        }

        return ParseFieldsArray(catalogText[dictStart..dictEnd]);
    }

    /// <summary>
    /// Determines whether the Catalog contains an inline <c>/AcroForm</c> dictionary whose
    /// <c>/Fields</c> entry is a direct array or absent — i.e. it can be updated in place
    /// without converting the AcroForm to an indirect object.
    /// </summary>
    public static bool HasUpdatableInlineAcroForm(ReadOnlySpan<byte> data, int catalogObjNum)
    {
        var (objStart, objEnd) = FindObjectBytes(data, catalogObjNum);
        if (objStart < 0)
        {
            return false;
        }

        string catalogText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
        var (dictStart, dictEnd) = FindInlineAcroFormBounds(catalogText);
        if (dictStart < 0)
        {
            return false;
        }

        string inlineDict = catalogText[dictStart..dictEnd];
        int fieldsKeyPos = inlineDict.IndexOf(PdfKeys.Fields, StringComparison.Ordinal);
        if (fieldsKeyPos < 0)
        {
            return true;
        }

        int cursor = fieldsKeyPos + PdfKeys.Fields.Length;
        while (cursor < inlineDict.Length && IsPdfWhitespaceChar(inlineDict[cursor]))
        {
            cursor++;
        }

        return cursor < inlineDict.Length && inlineDict[cursor] == '[';
    }

    /// <summary>
    /// Appends a field reference to the <c>/Fields</c> array of an inline <c>/AcroForm</c>
    /// dictionary in a Catalog object text. When <c>/Fields</c> is a direct array, the
    /// reference is appended before the closing bracket; when <c>/Fields</c> is absent, a
    /// new array is inserted. All other inline dictionary entries are preserved unchanged.
    /// Returns the input text unchanged when the Catalog has no inline AcroForm with an
    /// updatable <c>/Fields</c> entry (e.g. <c>/Fields</c> is an indirect reference).
    /// </summary>
    public static string AppendFieldToInlineAcroForm(string catalogText, string fieldRef)
    {
        var (dictStart, dictEnd) = FindInlineAcroFormBounds(catalogText);
        if (dictStart < 0)
        {
            return catalogText;
        }

        string inlineDict = catalogText[dictStart..dictEnd];
        string updatedDict = AppendFieldRefToInlineDict(inlineDict, fieldRef);
        if (ReferenceEquals(updatedDict, inlineDict))
        {
            return catalogText;
        }

        return string.Concat(catalogText.AsSpan(0, dictStart), updatedDict, catalogText.AsSpan(dictEnd));
    }

    /// <summary>
    /// Locates the inline <c>/AcroForm &lt;&lt;…&gt;&gt;</c> dictionary in a Catalog object
    /// text and returns its bounds (the dictionary delimiters inclusive), or (-1, -1) when
    /// the Catalog has no inline AcroForm. Nested dictionaries (e.g. /DR), literal strings,
    /// hexadecimal strings, and comments are handled by the shared depth-aware scanner.
    /// </summary>
    private static (int Start, int End) FindInlineAcroFormBounds(string catalogText)
    {
        int acroFormKeyPos = catalogText.IndexOf(PdfKeys.AcroForm, StringComparison.Ordinal);
        if (acroFormKeyPos < 0)
        {
            return (-1, -1);
        }

        int cursor = acroFormKeyPos + PdfKeys.AcroForm.Length;
        while (cursor < catalogText.Length && IsPdfWhitespaceChar(catalogText[cursor]))
        {
            cursor++;
        }

        if (cursor >= catalogText.Length || catalogText[cursor] != '<')
        {
            return (-1, -1);
        }

        int dictStart = cursor;
        int dictClose = FindDictEnd(catalogText, dictStart);
        if (dictClose < 0)
        {
            return (-1, -1);
        }

        return (dictStart, dictClose + 2);
    }

    /// <summary>
    /// Appends a field reference to the /Fields entry of an inline AcroForm dictionary.
    /// Returns the input dictionary unchanged when /Fields is an indirect reference.
    /// </summary>
    private static string AppendFieldRefToInlineDict(string inlineDict, string fieldRef)
    {
        int fieldsKeyPos = inlineDict.IndexOf(PdfKeys.Fields, StringComparison.Ordinal);
        if (fieldsKeyPos >= 0)
        {
            int cursor = fieldsKeyPos + PdfKeys.Fields.Length;
            while (cursor < inlineDict.Length && IsPdfWhitespaceChar(inlineDict[cursor]))
            {
                cursor++;
            }

            if (cursor < inlineDict.Length && inlineDict[cursor] == '[')
            {
                int closePos = FindClosingBracket(inlineDict, cursor);
                if (closePos > cursor)
                {
                    bool isEmpty = true;
                    for (int i = cursor + 1; i < closePos; i++)
                    {
                        if (!IsPdfWhitespaceChar(inlineDict[i]))
                        {
                            isEmpty = false;
                            break;
                        }
                    }

                    string insert = isEmpty ? fieldRef : $" {fieldRef}";
                    return string.Concat(inlineDict.AsSpan(0, closePos), insert, inlineDict.AsSpan(closePos));
                }
            }

            // /Fields is an indirect reference — cannot be updated in place.
            return inlineDict;
        }

        // No /Fields entry: insert a new array before the inline dictionary's closing >>.
        int dictClosePos = inlineDict.LastIndexOf(">>", StringComparison.Ordinal);
        if (dictClosePos < 0)
        {
            return inlineDict;
        }

        return string.Concat(inlineDict.AsSpan(0, dictClosePos), $" /Fields [{fieldRef}] ", inlineDict.AsSpan(dictClosePos));
    }

    /// <summary>
    /// Finds the bracket that closes the array opened at the given position, tracking
    /// nested arrays, dictionaries, literal and hexadecimal strings, and comments.
    /// Returns -1 when no closing bracket is found.
    /// </summary>
    private static int FindClosingBracket(string text, int openBracketPos) => FindArrayEnd(text, openBracketPos);

    /// <summary>
    /// Finds the index of the first '&gt;' of the <c>&gt;&gt;</c> that closes the dictionary
    /// opened at <paramref name="dictStart"/>, tracking nested dictionaries and arrays while
    /// skipping literal strings (with escape sequences and nesting), hexadecimal strings, and
    /// comments. Returns -1 when no closing delimiter is found.
    /// </summary>
    internal static int FindDictEnd(string text, int dictStart)
    {
        int depth = 0;
        int i = dictStart;
        while (i < text.Length)
        {
            char c = text[i];
            if (c == '%')
            {
                i = SkipComment(text, i);
                continue;
            }

            if (c == '(')
            {
                i = SkipLiteralString(text, i) + 1;
                continue;
            }

            if (c == '<')
            {
                if (i + 1 < text.Length && text[i + 1] == '<')
                {
                    depth++;
                    i += 2;
                    continue;
                }

                i = SkipHexString(text, i) + 1;
                continue;
            }

            if (c == '>' && i + 1 < text.Length && text[i + 1] == '>')
            {
                depth--;
                i += 2;
                if (depth == 0)
                {
                    return i - 2; // index of the first '>'
                }
                continue;
            }

            i++;
        }

        return -1;
    }

    /// <summary>
    /// Finds the index of the ']' that closes the array opened at <paramref name="openBracketPos"/>,
    /// tracking nested arrays and dictionaries while skipping literal strings, hexadecimal
    /// strings, and comments. Returns -1 when no closing bracket is found.
    /// </summary>
    internal static int FindArrayEnd(string text, int openBracketPos)
    {
        int depth = 0;
        int i = openBracketPos;
        while (i < text.Length)
        {
            char c = text[i];
            if (c == '%')
            {
                i = SkipComment(text, i);
                continue;
            }

            if (c == '(')
            {
                i = SkipLiteralString(text, i) + 1;
                continue;
            }

            if (c == '<')
            {
                if (i + 1 < text.Length && text[i + 1] == '<')
                {
                    int dictEnd = FindDictEnd(text, i);
                    if (dictEnd < 0)
                    {
                        return -1;
                    }

                    i = dictEnd + 2;
                    continue;
                }

                i = SkipHexString(text, i) + 1;
                continue;
            }

            if (c == '[')
            {
                depth++;
                i++;
                continue;
            }

            if (c == ']')
            {
                depth--;
                i++;
                if (depth == 0)
                {
                    return i - 1;
                }
                continue;
            }

            i++;
        }

        return -1;
    }

    /// <summary>
    /// Skips a comment (% to end of line) starting at <paramref name="pos"/>
    /// and returns the index of the line terminator (or the end of the text).
    /// </summary>
    internal static int SkipComment(string text, int pos)
    {
        int i = pos;
        while (i < text.Length && text[i] != '\n' && text[i] != '\r')
        {
            i++;
        }

        return i;
    }

    /// <summary>
    /// Skips a literal string starting at the '(' at <paramref name="openParenPos"/>,
    /// honouring escape sequences and nested parentheses, and returns the index of the
    /// closing ')'. Returns the last character index when the string is unterminated.
    /// </summary>
    internal static int SkipLiteralString(string text, int openParenPos)
    {
        int depth = 1;
        int i = openParenPos + 1;
        while (i < text.Length && depth > 0)
        {
            char c = text[i];
            if (c == '\\')
            {
                if (i + 2 < text.Length && text[i + 1] == '\r' && text[i + 2] == '\n')
                {
                    i += 3; // line continuation \r\n
                }
                else
                {
                    i += 2; // escaped character
                }
                continue;
            }

            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }

            i++;
        }

        return text.Length - 1;
    }

    /// <summary>
    /// Skips a hexadecimal string starting at the '&lt;' at <paramref name="openAnglePos"/>
    /// and returns the index of the closing '&gt;'. Returns the last character index when
    /// the string is unterminated.
    /// </summary>
    internal static int SkipHexString(string text, int openAnglePos)
    {
        int i = openAnglePos + 1;
        while (i < text.Length && text[i] != '>')
        {
            i++;
        }

        return i < text.Length ? i : text.Length - 1;
    }

    /// <summary>
    /// Finds the first <c>/Type /Page</c> object in the PDF data and returns
    /// its object number, dictionary start offset, and object end offset.
    /// Returns the LAST revision of the page for incremental update correctness.
    /// </summary>
    public static (int ObjNum, int DictStart, int DictEnd) FindFirstPageObject(ReadOnlySpan<byte> data)
    {
        int typePos = FindPageTypeToken(data, 0);
        if (typePos >= 0)
        {
            int dictStart = -1;
            for (int pos = typePos - 1; pos >= 1; pos--)
            {
                if (data[pos] == (byte)'<' && data[pos - 1] == (byte)'<')
                {
                    dictStart = pos - 1;
                    break;
                }
            }
            if (dictStart >= 0)
            {
                int pageObjNum = FindObjNumBefore(data, dictStart);
                if (pageObjNum > 0)
                {
                    // Use FindObjectBytes to get the LAST revision of this page object.
                    var (latestStart, latestEnd) = FindObjectBytes(data, pageObjNum);
                    if (latestStart >= 0)
                    {
                        int latestDictStart = -1;
                        for (int pos = latestStart; pos < latestEnd - 1; pos++)
                        {
                            if (data[pos] == (byte)'<' && data[pos + 1] == (byte)'<')
                            {
                                latestDictStart = pos;
                                break;
                            }
                        }
                        if (latestDictStart >= 0)
                        {
                            return (ObjNum: pageObjNum, DictStart: latestDictStart, DictEnd: latestEnd);
                        }
                    }
                }
            }
        }

        // Fallback: page objects may be in compressed ObjStm. Find the first page from
        // Catalog → /Pages → /Kids chain. The page obj num is sufficient for incremental
        // updates even though the page content must be extracted from ObjStm separately.
        int firstPageObjNum = FindFirstPageObjNumFromCatalog(data);
        if (firstPageObjNum > 0)
        {
            // Check if the page exists as a regular object (may have been written in a prior update)
            var (objStart, objEnd) = FindObjectBytes(data, firstPageObjNum);
            if (objStart >= 0)
            {
                int ds = -1;
                for (int pos = objStart; pos < objEnd - 1; pos++)
                {
                    if (data[pos] == (byte)'<' && data[pos + 1] == (byte)'<')
                    {
                        ds = pos;
                        break;
                    }
                }
                if (ds >= 0)
                {
                    return (ObjNum: firstPageObjNum, DictStart: ds, DictEnd: objEnd);
                }
            }

            // Page is compressed in ObjStm — return obj num with sentinel DictStart/End.
            // Callers that need the dict content must use ExtractObjectFromObjStm.
            return (ObjNum: firstPageObjNum, DictStart: -1, DictEnd: -1);
        }

        return (ObjNum: -1, DictStart: -1, DictEnd: -1);
    }

    /// <summary>
    /// Finds the first page object number by traversing Catalog → /Pages → /Kids,
    /// handling both uncompressed and ObjStm-compressed objects.
    /// </summary>
    internal static int FindFirstPageObjNumFromCatalog(ReadOnlySpan<byte> data)
    {
        int catalogObjNum = FindRootObjectNumber(data);
        if (catalogObjNum <= 0)
        {
            return -1;
        }

        // Get catalog content (may be compressed)
        string? catalogText = GetObjectContent(data, catalogObjNum);
        if (catalogText == null)
        {
            return -1;
        }

        // Extract /Pages reference
        int pagesObjNum = ExtractObjReference(catalogText, "/Pages");
        if (pagesObjNum <= 0)
        {
            return -1;
        }

        // Get Pages content (may be compressed)
        string? pagesText = GetObjectContent(data, pagesObjNum);
        if (pagesText == null)
        {
            return -1;
        }

        // Extract the /Kids child references
        int kidsPos = pagesText.IndexOf(PdfKeys.Kids, StringComparison.Ordinal);
        if (kidsPos < 0)
        {
            return -1;
        }

        List<int> childObjNums = ParseKidsArrayReferences(pagesText, kidsPos);
        return childObjNums.Count > 0 ? childObjNums[0] : -1;
    }

    /// <summary>
    /// Finds the Nth page object number (1-based) by traversing Catalog → /Pages → /Kids.
    /// Returns -1 if the page number exceeds the document's page count.
    /// </summary>
    internal static int FindNthPageObjNum(ReadOnlySpan<byte> data, int pageNumber)
    {
        if (pageNumber < 1)
        {
            return -1;
        }

        int catalogObjNum = FindRootObjectNumber(data);
        if (catalogObjNum <= 0)
        {
            return -1;
        }

        string? catalogText = GetObjectContent(data, catalogObjNum);
        if (catalogText == null)
        {
            return -1;
        }

        int pagesObjNum = ExtractObjReference(catalogText, "/Pages");
        if (pagesObjNum <= 0)
        {
            return -1;
        }

        string? pagesText = GetObjectContent(data, pagesObjNum);
        if (pagesText == null)
        {
            return -1;
        }

        // Extract the /Kids child references
        int kidsPos = pagesText.IndexOf(PdfKeys.Kids, StringComparison.Ordinal);
        if (kidsPos < 0)
        {
            return -1;
        }

        List<int> childObjNums = ParseKidsArrayReferences(pagesText, kidsPos);
        if (pageNumber > childObjNums.Count)
        {
            return -1;
        }

        return childObjNums[pageNumber - 1];
    }

    /// <summary>
    /// Parses the <c>/Kids</c> array that follows the given <c>/Kids</c> key position in a
    /// <c>/Pages</c> dictionary text, using PDF token rules rather than line-oriented matching.
    /// Each child entry is an indirect reference (<c>objNum genNum R</c>). Entries may be
    /// separated by any PDF whitespace character (NUL, TAB, LF, FF, CR, SP — ISO 32000-1 §7.2.2),
    /// and comments (<c>%</c> to end of line) are skipped where PDF syntax permits them.
    /// Line endings are not required between entries.
    /// </summary>
    /// <param name="pagesText">The text of the <c>/Pages</c> object (dictionary or extracted ObjStm content).</param>
    /// <param name="kidsKeyPos">The position of the <c>/Kids</c> key within <paramref name="pagesText"/>.</param>
    /// <returns>The object numbers of the /Kids children, in array order.</returns>
    private static List<int> ParseKidsArrayReferences(string pagesText, int kidsKeyPos)
    {
        List<int> childObjNums = [];

        int openBracket = pagesText.IndexOf('[', kidsKeyPos);
        if (openBracket < 0)
        {
            return childObjNums;
        }

        int cursor = openBracket + 1;
        while (cursor < pagesText.Length)
        {
            cursor = SkipPdfSeparators(pagesText, cursor);
            if (cursor >= pagesText.Length || pagesText[cursor] == ']')
            {
                break;
            }

            if (TryParseIndirectReference(pagesText, ref cursor, out int objNum))
            {
                childObjNums.Add(objNum);
                continue;
            }

            // Malformed entry: skip this token and resynchronise at the next separator.
            while (cursor < pagesText.Length && pagesText[cursor] != ']' && !IsPdfWhitespaceChar(pagesText[cursor]) && pagesText[cursor] != '%')
            {
                cursor++;
            }
        }

        return childObjNums;
    }

    /// <summary>
    /// Parses one indirect reference (<c>objNum genNum R</c>) at the current cursor position.
    /// On success, advances the cursor past the reference and returns the object number.
    /// On failure, the cursor is left at the first unparsable position.
    /// </summary>
    private static bool TryParseIndirectReference(string text, ref int cursor, out int objNum)
    {
        objNum = 0;
        int numStart = cursor;

        while (cursor < text.Length && IsAsciiDigit(text[cursor]))
        {
            if (objNum > int.MaxValue / 10)
            {
                // Overflow: consume the remaining digits and fail.
                while (cursor < text.Length && IsAsciiDigit(text[cursor]))
                {
                    cursor++;
                }

                return false;
            }

            objNum = (objNum * 10) + (text[cursor] - '0');
            cursor++;
        }

        // Object numbers are positive; "0" alone is not a valid reference.
        if (numStart == cursor || objNum <= 0)
        {
            return false;
        }

        cursor = SkipPdfSeparators(text, cursor);

        // Generation number.
        int genStart = cursor;
        while (cursor < text.Length && IsAsciiDigit(text[cursor]))
        {
            cursor++;
        }

        if (genStart == cursor)
        {
            return false;
        }

        cursor = SkipPdfSeparators(text, cursor);

        if (cursor >= text.Length || text[cursor] != 'R')
        {
            return false;
        }

        cursor++;
        return true;
    }

    /// <summary>
    /// Advances the cursor past PDF whitespace (NUL, TAB, LF, FF, CR, SP — ISO 32000-1 §7.2.2)
    /// and comments (<c>%</c> to end of line).
    /// </summary>
    private static int SkipPdfSeparators(string text, int cursor)
    {
        while (cursor < text.Length)
        {
            char c = text[cursor];
            if (IsPdfWhitespaceChar(c))
            {
                cursor++;
            }
            else if (c == '%')
            {
                // Comment runs to end of line (or end of the object text).
                while (cursor < text.Length && text[cursor] != '\n' && text[cursor] != '\r')
                {
                    cursor++;
                }
            }
            else
            {
                break;
            }
        }

        return cursor;
    }

    /// <summary>
    /// Determines whether a character is a PDF whitespace character
    /// (NUL, TAB, LF, FF, CR, SP — ISO 32000-1 §7.2.2).
    /// </summary>
    private static bool IsPdfWhitespaceChar(char c) => c is '\0' or '\t' or '\n' or '\f' or '\r' or ' ';

    /// <summary>
    /// Determines whether a character is an ASCII decimal digit. PDF numbers are ASCII-only.
    /// </summary>
    private static bool IsAsciiDigit(char c) => c is >= '0' and <= '9';

    /// <summary>
    /// Gets the text content of a PDF object, trying regular object bytes first,
    /// then falling back to ObjStm extraction.
    /// </summary>
    private static string? GetObjectContent(ReadOnlySpan<byte> data, int objNum)
    {
        var (objStart, objEnd) = FindObjectBytes(data, objNum);
        if (objStart >= 0)
        {
            return Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
        }

        return ExtractObjectFromObjStm(data, objNum);
    }

    /// <summary>
    /// Extracts an indirect object reference number from a dictionary key (e.g., "/Pages 2 0 R" → 2).
    /// </summary>
    private static int ExtractObjReference(string dictText, string key)
    {
        int keyPos = dictText.IndexOf(key, StringComparison.Ordinal);
        if (keyPos < 0)
        {
            return -1;
        }

        int cursor = keyPos + key.Length;
        while (cursor < dictText.Length && (dictText[cursor] == ' ' || dictText[cursor] == '\n' || dictText[cursor] == '\r'))
        {
            cursor++;
        }

        int numStart = cursor;
        while (cursor < dictText.Length && char.IsDigit(dictText[cursor]))
        {
            cursor++;
        }

        if (numStart < cursor && int.TryParse(dictText.AsSpan(numStart, cursor - numStart), out int objNum))
        {
            return objNum;
        }

        return -1;
    }

    /// <summary>
    /// Parses the effective page width for signature positioning.
    /// Checks /CropBox first (visible region per §8.3.2.2), then /MediaBox (§8.3.2.1).
    /// Follows /Parent chain for inherited values. Falls back to 612 (US Letter width).
    /// </summary>
    public static float ParseMediaBoxWidth(ReadOnlySpan<byte> data, string pageDict)
    {
        // Try /CropBox on the page dict first (defines visible region)
        float width = ExtractBoxWidth(pageDict, "/CropBox");
        if (width > 0)
        {
            return width;
        }

        // Try /MediaBox on the page dict
        width = ExtractBoxWidth(pageDict, "/MediaBox");
        if (width > 0)
        {
            return width;
        }

        // Follow /Parent chain for inherited MediaBox/CropBox
        width = ResolveInheritedBoxWidth(data, pageDict);
        if (width > 0)
        {
            return width;
        }

        // Last resort: scan the whole PDF for any /MediaBox
        string fullText = Encoding.Latin1.GetString(data);
        width = ExtractBoxWidth(fullText, "/MediaBox");
        return width > 0 ? width : 612f;
    }

    /// <summary>
    /// Parses the effective page height for signature positioning.
    /// Same inheritance rules as width.
    /// </summary>
    public static float ParsePageHeight(ReadOnlySpan<byte> data, string pageDict)
    {
        float height = ExtractBoxHeight(pageDict, "/CropBox");
        if (height > 0)
        {
            return height;
        }

        height = ExtractBoxHeight(pageDict, "/MediaBox");
        if (height > 0)
        {
            return height;
        }

        // Follow /Parent chain for inherited MediaBox/CropBox
        height = ResolveInheritedBoxHeight(data, pageDict);
        if (height > 0)
        {
            return height;
        }

        // Scan full PDF as fallback
        string fullText = Encoding.Latin1.GetString(data);
        height = ExtractBoxHeight(fullText, "/MediaBox");
        return height > 0 ? height : 792f; // US Letter height
    }

    /// <summary>
    /// Extracts the /Rotate value from the page dictionary (§8.3.2.4).
    /// Values: 0, 90, 180, 270. Returns 0 if not found.
    /// </summary>
    public static int ParsePageRotation(ReadOnlySpan<byte> data, string pageDict)
    {
        int rotate = ExtractIntValue(pageDict, "/Rotate");
        if (rotate != 0)
        {
            return NormalizeRotation(rotate);
        }

        // Check /Parent chain for inherited /Rotate
        int parentObjNum = ExtractIntValue(pageDict, "/Parent");
        if (parentObjNum <= 0)
        {
            return 0;
        }

        for (int depth = 0; depth < 10; depth++)
        {
            var (objStart, objEnd) = FindObjectBytes(data, parentObjNum);
            if (objStart < 0)
            {
                break;
            }

            string parentText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
            rotate = ExtractIntValue(parentText, "/Rotate");
            if (rotate != 0)
            {
                return NormalizeRotation(rotate);
            }

            parentObjNum = ExtractIntValue(parentText, "/Parent");
            if (parentObjNum <= 0)
            {
                break;
            }
        }

        return 0;
    }

    /// <summary>
    /// Counts the number of existing visible signature annotations (with non-zero <c>/Rect</c>)
    /// by scanning for <c>/FT /Sig</c> widget annotations in the PDF data. Each widget's own
    /// dictionary is located with the string-aware scanner and only a top-level /Rect entry is
    /// considered, so nested dictionaries and long entries cannot skew the count.
    /// </summary>
    public static int CountVisibleSignatureAnnotations(ReadOnlySpan<byte> data)
    {
        string text = Encoding.Latin1.GetString(data);
        int count = 0;
        int searchPos = 0;

        while (searchPos < text.Length)
        {
            int matchPos = text.IndexOf(PdfKeys.FtSig, searchPos, StringComparison.Ordinal);
            if (matchPos < 0)
            {
                break;
            }

            int dictStart = FindEnclosingDictStart(text, matchPos);
            if (dictStart >= 0)
            {
                int dictEnd = FindDictEnd(text, dictStart);
                if (dictEnd >= dictStart && HasNonZeroRect(text[dictStart..(dictEnd + 2)]))
                {
                    count++;
                }
            }

            searchPos = matchPos + PdfKeys.FtSig.Length;
        }

        return count;
    }

    /// <summary>
    /// Finds the start of the dictionary enclosing <paramref name="nearPos"/> by scanning
    /// backwards, skipping literal strings and comments, and verifying the candidate
    /// dictionary actually encloses the position.
    /// </summary>
    private static int FindEnclosingDictStart(string text, int nearPos)
    {
        for (int pos = nearPos; pos >= 1; pos--)
        {
            char c = text[pos];
            if (c == ')')
            {
                pos = BacktrackLiteralString(text, pos);
                continue;
            }

            if (c == '<' && text[pos - 1] == '<')
            {
                int candidate = pos - 1;
                if (IsInsideComment(text, candidate))
                {
                    continue;
                }

                int end = FindDictEnd(text, candidate);
                if (end >= nearPos)
                {
                    return candidate;
                }
            }
        }

        return -1;
    }

    /// <summary>
    /// Determines whether a widget dictionary declares a visible rectangle
    /// (a top-level /Rect array whose value is not [0 0 0 0]).
    /// </summary>
    private static bool HasNonZeroRect(string widgetDict)
    {
        int rectKeyPos = FindTopLevelKey(widgetDict, "/Rect");
        if (rectKeyPos < 0)
        {
            return false;
        }

        int cursor = rectKeyPos + "/Rect".Length;
        while (cursor < widgetDict.Length && IsPdfWhitespaceChar(widgetDict[cursor]))
        {
            cursor++;
        }

        if (cursor >= widgetDict.Length || widgetDict[cursor] != '[')
        {
            return false;
        }

        int closePos = FindArrayEnd(widgetDict, cursor);
        if (closePos <= cursor)
        {
            return false;
        }

        string content = widgetDict.Substring(cursor + 1, closePos - cursor - 1);
        string[] parts = content.Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
        return string.Join(' ', parts) != "0 0 0 0";
    }

    /// <summary>
    /// Backtracks from a closing ')' over the literal string it terminates, honouring
    /// escape sequences and nested parentheses. Returns the index before the matching '(',
    /// or -1 when no opening parenthesis is found.
    /// </summary>
    private static int BacktrackLiteralString(string text, int closePos)
    {
        int depth = 1;
        int i = closePos - 1;
        while (i >= 0 && depth > 0)
        {
            char c = text[i];
            if (c == ')')
            {
                depth++;
            }
            else if (c == '(')
            {
                depth--;
                if (depth == 0)
                {
                    return i - 1;
                }
            }
            else if (c == '\\')
            {
                // Skip the escaped character immediately before the backslash.
                i--;
            }

            i--;
        }

        return -1;
    }

    /// <summary>
    /// Determines whether the given position is inside a comment (% to end of line),
    /// by scanning backwards to the start of the line.
    /// </summary>
    private static bool IsInsideComment(string text, int pos)
    {
        int i = pos - 1;
        while (i >= 0 && text[i] != '\n' && text[i] != '\r')
        {
            if (text[i] == '%')
            {
                return true;
            }

            i--;
        }

        return false;
    }

    /// <summary>
    /// Finds the <c>startxref</c> offset in the last 1024 bytes of the input PDF.
    /// </summary>
    public static async Task<long> FindPrevXRefAsync(Stream stream, CancellationToken ct)
    {
        const int TailSize = 1024;
        long readOffset = Math.Max(0L, stream.Length - TailSize);
        stream.Seek(readOffset, SeekOrigin.Begin);

        byte[] buffer = new byte[(int)Math.Min(TailSize, stream.Length)];
        Span<byte> tail = buffer.AsSpan(0, await stream.ReadAsync(buffer, ct).ConfigureAwait(false));

        ReadOnlySpan<byte> startxrefToken = "startxref"u8;
        int tokenPos = tail.LastIndexOf(startxrefToken);
        if (tokenPos < 0)
        {
            return 0L;
        }

        int cursor;
        for (cursor = tokenPos + startxrefToken.Length; cursor < tail.Length && (tail[cursor] == (byte)' ' || tail[cursor] == (byte)'\n' || tail[cursor] == (byte)'\r'); cursor++)
        {
        }

        long xrefOffset = 0L;
        while (cursor < tail.Length && tail[cursor] >= (byte)'0' && tail[cursor] <= (byte)'9')
        {
            if (xrefOffset > long.MaxValue / 10)
            {
                return 0L;
            }

            xrefOffset = xrefOffset * 10 + (tail[cursor++] - '0');
        }

        return xrefOffset;
    }

    /// <summary>
    /// Determines whether the PDF uses cross-reference streams (§7.5.8) or classic xref tables.
    /// When true, incremental updates should also use xref streams for compatibility.
    /// </summary>
    public static bool UsesXRefStreams(ReadOnlySpan<byte> data)
    {
        // Find the last startxref value
        ReadOnlySpan<byte> startxrefToken = "startxref"u8;
        int tokenPos = data.LastIndexOf(startxrefToken);
        if (tokenPos < 0)
        {
            return false;
        }

        int cursor = tokenPos + startxrefToken.Length;
        while (cursor < data.Length && (data[cursor] == (byte)' ' || data[cursor] == (byte)'\n' || data[cursor] == (byte)'\r'))
        {
            cursor++;
        }

        long xrefOffset = 0L;
        while (cursor < data.Length && data[cursor] >= (byte)'0' && data[cursor] <= (byte)'9')
        {
            if (xrefOffset > long.MaxValue / 10)
            {
                return false;
            }

            xrefOffset = xrefOffset * 10 + (data[cursor++] - '0');
        }

        if (xrefOffset <= 0 || xrefOffset >= data.Length)
        {
            return false;
        }

        // Classic xref tables start with "xref"
        ReadOnlySpan<byte> xrefKeyword = "xref"u8;
        if (data.Slice((int)xrefOffset).StartsWith(xrefKeyword))
        {
            return false;
        }

        // Xref streams start with "N 0 obj" and contain /Type /XRef
        ReadOnlySpan<byte> typeXRef1 = "/Type /XRef"u8;
        ReadOnlySpan<byte> typeXRef2 = "/Type/XRef"u8;
        int searchEnd = Math.Min((int)xrefOffset + 500, data.Length);
        var region = data.Slice((int)xrefOffset, searchEnd - (int)xrefOffset);
        return region.IndexOf(typeXRef1) >= 0 || region.IndexOf(typeXRef2) >= 0;
    }

    /// <summary>
    /// Parses the <c>/Fields [N 0 R ...]</c> array from a PDF object text,
    /// returning a list of indirect references like <c>"5 0 R"</c>.
    /// The array must directly follow the <c>/Fields</c> key; when <c>/Fields</c>
    /// holds an indirect reference (or anything else), an empty list is returned
    /// so callers can fall back to <see cref="ResolveIndirectFields"/> instead of
    /// mistaking a later key's array for the fields list.
    /// </summary>
    public static List<string> ParseFieldsArray(string objText)
    {
        List<string> references = new List<string>();
        int fieldsKeyPos = objText.IndexOf(PdfKeys.Fields, StringComparison.Ordinal);
        if (fieldsKeyPos < 0)
        {
            return references;
        }

        int cursor = fieldsKeyPos + PdfKeys.Fields.Length;
        while (cursor < objText.Length && IsPdfWhitespaceChar(objText[cursor]))
        {
            cursor++;
        }

        if (cursor >= objText.Length || objText[cursor] != '[')
        {
            return references;
        }

        int arrayOpenPos = cursor;
        int arrayClosePos = FindArrayEnd(objText, arrayOpenPos);
        if (arrayClosePos <= arrayOpenPos)
        {
            return references;
        }

        int contentStart = arrayOpenPos + 1;
        string arrayContent = objText.Substring(contentStart, arrayClosePos - contentStart).Trim();
        if (string.IsNullOrEmpty(arrayContent))
        {
            return references;
        }

        string[] tokens = arrayContent.Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i + 2 < tokens.Length; i++)
        {
            if (int.TryParse(tokens[i], out _) && tokens[i + 1] == "0" && tokens[i + 2] == "R")
            {
                references.Add(tokens[i] + " 0 R");
                i += 2;
            }
        }

        return references;
    }

    /// <summary>
    /// Resolves an indirect <c>/Fields N 0 R</c> reference from an AcroForm dictionary.
    /// When <c>/Fields</c> points to a separate array object instead of containing an inline array,
    /// this method resolves the referenced object and parses its contents.
    /// Returns the field references, or an empty list if the pattern is not found.
    /// </summary>
    public static List<string> ResolveIndirectFields(ReadOnlySpan<byte> data, string acroFormText)
    {
        int fieldsKeyPos = acroFormText.IndexOf(PdfKeys.Fields, StringComparison.Ordinal);
        if (fieldsKeyPos < 0)
        {
            return [];
        }

        int cursor = fieldsKeyPos + PdfKeys.Fields.Length;
        // Skip whitespace
        while (cursor < acroFormText.Length && (acroFormText[cursor] == ' ' || acroFormText[cursor] == '\n' || acroFormText[cursor] == '\r' || acroFormText[cursor] == '\t'))
        {
            cursor++;
        }

        // If it's an inline array, ParseFieldsArray handles it
        if (cursor >= acroFormText.Length || acroFormText[cursor] == '[')
        {
            return [];
        }

        // Check for indirect reference (digit starts object number)
        if (!char.IsDigit(acroFormText[cursor]))
        {
            return [];
        }

        int fieldsObjNum = 0;
        while (cursor < acroFormText.Length && char.IsDigit(acroFormText[cursor]))
        {
            if (fieldsObjNum > int.MaxValue / 10)
            {
                return [];
            }

            fieldsObjNum = fieldsObjNum * 10 + (acroFormText[cursor++] - '0');
        }

        if (fieldsObjNum <= 0)
        {
            return [];
        }

        // Resolve the indirect object
        var (refStart, refEnd) = FindObjectBytes(data, fieldsObjNum);
        if (refStart >= 0)
        {
            string refObj = Encoding.Latin1.GetString(data.Slice(refStart, refEnd - refStart));
            return ParseReferencesFromArray(refObj);
        }

        // Try in compressed Object Streams
        string? compressedContent = ExtractObjectFromObjStm(data, fieldsObjNum);
        if (compressedContent != null)
        {
            return ParseReferencesFromArray(compressedContent);
        }

        return [];
    }

    /// <summary>
    /// Parses indirect references (N 0 R) from a text that contains a PDF array [...].
    /// </summary>
    private static List<string> ParseReferencesFromArray(string text)
    {
        List<string> references = [];
        int openBracket = text.IndexOf('[');
        int closeBracket = text.LastIndexOf(']');
        if (openBracket < 0 || closeBracket <= openBracket)
        {
            return references;
        }

        string arrayContent = text.Substring(openBracket + 1, closeBracket - openBracket - 1).Trim();
        if (string.IsNullOrEmpty(arrayContent))
        {
            return references;
        }

        string[] tokens = arrayContent.Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i + 2 < tokens.Length; i++)
        {
            if (int.TryParse(tokens[i], out _) && tokens[i + 1] == "0" && tokens[i + 2] == "R")
            {
                references.Add(tokens[i] + " 0 R");
                i += 2;
            }
        }

        return references;
    }

    /// <summary>
    /// Removes a key-value entry from a PDF dictionary string, honouring PDF token rules:
    /// the whole value is removed (dictionaries, arrays, literal strings, hexadecimal
    /// strings, names, and indirect references may span multiple lines). Normalises CRLF
    /// to LF so the search works uniformly across source PDFs produced on Windows / by
    /// iText / Adobe (CRLF) and macOS / Linux (LF). Returns the input unchanged when the
    /// key is not found.
    /// </summary>
    public static string RemoveKeyFromDict(string obj, string key)
    {
        string normalised = obj.Replace("\r\n", "\n", StringComparison.Ordinal);
        int keyPos = FindTopLevelKey(normalised, key);
        if (keyPos < 0)
        {
            return obj;
        }

        int cursor = keyPos + key.Length;
        while (cursor < normalised.Length && IsPdfWhitespaceChar(normalised[cursor]))
        {
            cursor++;
        }

        int valueEnd;
        if (cursor < normalised.Length)
        {
            char c = normalised[cursor];
            if (c == '<' && cursor + 1 < normalised.Length && normalised[cursor + 1] == '<')
            {
                // Dictionary value.
                int dictEnd = FindDictEnd(normalised, cursor);
                valueEnd = dictEnd >= 0 ? dictEnd + 2 : normalised.Length;
            }
            else if (c == '<')
            {
                // Hexadecimal string value.
                valueEnd = SkipHexString(normalised, cursor) + 1;
            }
            else if (c == '[')
            {
                // Array value.
                int arrayEnd = FindArrayEnd(normalised, cursor);
                valueEnd = arrayEnd >= 0 ? arrayEnd + 1 : normalised.Length;
            }
            else if (c == '(')
            {
                // Literal string value.
                valueEnd = SkipLiteralString(normalised, cursor) + 1;
            }
            else if (IsAsciiDigit(c))
            {
                // Indirect reference: objNum genNum R (tokens may be separated by whitespace).
                valueEnd = cursor;
                while (valueEnd < normalised.Length && IsAsciiDigit(normalised[valueEnd]))
                {
                    valueEnd++;
                }
                while (valueEnd < normalised.Length && IsHorizontalSpace(normalised[valueEnd]))
                {
                    valueEnd++;
                }
                if (valueEnd < normalised.Length && IsAsciiDigit(normalised[valueEnd]))
                {
                    while (valueEnd < normalised.Length && IsAsciiDigit(normalised[valueEnd]))
                    {
                        valueEnd++;
                    }
                    while (valueEnd < normalised.Length && IsHorizontalSpace(normalised[valueEnd]))
                    {
                        valueEnd++;
                    }
                    if (valueEnd < normalised.Length && normalised[valueEnd] == 'R')
                    {
                        valueEnd++;
                    }
                }
            }
            else
            {
                // Name or other single token.
                valueEnd = cursor;
                while (valueEnd < normalised.Length && !IsPdfWhitespaceChar(normalised[valueEnd]))
                {
                    valueEnd++;
                }
            }
        }
        else
        {
            valueEnd = cursor;
        }

        // Also strip trailing horizontal whitespace after the value.
        int removeEnd = valueEnd;
        while (removeEnd < normalised.Length && IsHorizontalSpace(normalised[removeEnd]))
        {
            removeEnd++;
        }

        return string.Concat(normalised.AsSpan(0, keyPos), normalised.AsSpan(removeEnd));
    }

    /// <summary>
    /// Finds a top-level dictionary key (at depth 1, directly inside the outermost
    /// dictionary) by token-aware scanning that skips literal strings, hexadecimal
    /// strings, comments, and nested dictionaries/arrays. Returns -1 when not found.
    /// </summary>
    internal static int FindTopLevelKey(string text, string key)
    {
        int depth = 0;
        int i = 0;
        while (i < text.Length)
        {
            char c = text[i];
            if (c == '%')
            {
                i = SkipComment(text, i);
                continue;
            }

            if (c == '(')
            {
                i = SkipLiteralString(text, i) + 1;
                continue;
            }

            if (c == '<')
            {
                if (i + 1 < text.Length && text[i + 1] == '<')
                {
                    depth++;
                    i += 2;
                    continue;
                }

                i = SkipHexString(text, i) + 1;
                continue;
            }

            if (c == '[')
            {
                depth++;
                i++;
                continue;
            }

            if (c == '>')
            {
                if (i + 1 < text.Length && text[i + 1] == '>')
                {
                    // The text may start in the middle of a document (e.g. a sliced
                    // object), so never let the depth go negative.
                    if (depth > 0)
                    {
                        depth--;
                    }

                    i += 2;
                    continue;
                }

                i++;
                continue;
            }

            if (c == ']')
            {
                depth--;
                i++;
                continue;
            }

            if (c == '/' && depth == 1 && text.AsSpan(i).StartsWith(key, StringComparison.Ordinal))
            {
                int after = i + key.Length;
                if (after >= text.Length
                    || IsPdfWhitespaceChar(text[after])
                    || text[after] == '('
                    || text[after] == '<'
                    || text[after] == '[')
                {
                    return i;
                }
            }

            i++;
        }

        return -1;
    }

    /// <summary>
    /// Determines whether a character is horizontal whitespace (SP or TAB).
    /// </summary>
    private static bool IsHorizontalSpace(char c) => c is ' ' or '\t';

    /// <summary>
    /// Inserts a new key-value line into a PDF dictionary string, just before the closing
    /// <c>&gt;&gt;\nendobj</c>. CRLF input is normalised to LF so the sentinel matches
    /// source PDFs produced on Windows / by iText / Adobe. If the sentinel is not found
    /// (e.g. unusual line endings), falls back to a depth-aware search for the closing
    /// <c>&gt;&gt;</c> of the top-level dictionary so the insert lands at the correct
    /// level instead of inside a nested dictionary.
    /// </summary>
    public static string InsertIntoDict(string obj, string toInsert)
    {
        string normalised = obj.Replace("\r\n", "\n", StringComparison.Ordinal);
        int insertPos = normalised.LastIndexOf(">>\nendobj", StringComparison.Ordinal);
        if (insertPos < 0)
        {
            insertPos = FindOutermostDictClose(normalised);
        }
        if (insertPos < 0)
        {
            return obj;
        }

        return string.Concat(normalised.AsSpan(0, insertPos), toInsert, normalised.AsSpan(insertPos));
    }

    /// <summary>
    /// Finds the position of the next top-level PDF dictionary key (starting with '/')
    /// or the end-of-dictionary marker ('&gt;&gt;'), skipping nested structures, literal
    /// strings, hexadecimal strings, and comments.
    /// </summary>
    internal static int FindNextTopLevelKey(string text, int start)
    {
        int depth = 0;
        int i = start;
        while (i < text.Length)
        {
            char c = text[i];
            if (c == '%')
            {
                i = SkipComment(text, i);
                continue;
            }

            if (c == '(')
            {
                i = SkipLiteralString(text, i) + 1;
                continue;
            }

            if (c == '<')
            {
                if (i + 1 < text.Length && text[i + 1] == '<')
                {
                    depth++;
                    i += 2;
                    continue;
                }

                i = SkipHexString(text, i) + 1;
                continue;
            }

            if (c == '[')
            {
                depth++;
                i++;
                continue;
            }

            if (c == '>')
            {
                if (i + 1 < text.Length && text[i + 1] == '>')
                {
                    if (depth > 0)
                    {
                        depth--;
                        i += 2;
                        continue;
                    }

                    return i;
                }

                i++;
                continue;
            }

            if (c == ']')
            {
                if (depth > 0)
                {
                    depth--;
                }

                i++;
                continue;
            }

            if (c == '/' && depth == 0 && i > start)
            {
                return i;
            }

            i++;
        }

        return text.Length;
    }

    /// <summary>
    /// Finds the offset of the closing <c>&gt;&gt;</c> of the top-level dictionary by
    /// tracking dictionary nesting depth. Returns the last <c>&gt;&gt;</c> that brings
    /// the depth from 1 back to 0, or -1 if no top-level dictionary is found.
    /// Avoids matching a <c>&gt;&gt;</c> inside a nested dictionary value such as
    /// <c>/DR &lt;&lt; /Font &lt;&lt; … &gt;&gt; &gt;&gt;</c>, and ignores <c>&lt;&lt;</c>/<c>&gt;&gt;</c>
    /// sequences inside literal strings, hexadecimal strings, and comments.
    /// </summary>
    public static int FindOutermostDictClose(string text)
    {
        // Locate the first top-level '<<', then let the depth-aware scanner find its
        // matching close (nested dictionaries are skipped internally).
        int firstOpen = -1;
        int i = 0;
        while (i < text.Length)
        {
            char c = text[i];
            if (c == '%')
            {
                i = SkipComment(text, i);
                continue;
            }

            if (c == '(')
            {
                i = SkipLiteralString(text, i) + 1;
                continue;
            }

            if (c == '<')
            {
                if (i + 1 < text.Length && text[i + 1] == '<')
                {
                    firstOpen = i;
                    break;
                }

                i = SkipHexString(text, i) + 1;
                continue;
            }

            i++;
        }

        if (firstOpen < 0)
        {
            return -1;
        }

        return FindDictEnd(text, firstOpen);
    }

    /// <summary>
    /// Validates that a signature field object has the required /FT /Sig structure
    /// and that /V (if present) points to a valid /Type /Sig dictionary (§12.7.4.4).
    /// Returns a list of warnings (empty if the field is valid).
    /// </summary>
    public static List<string> ValidateSignatureField(ReadOnlySpan<byte> data, int objNum)
    {
        var warnings = new List<string>();
        var (objStart, objEnd) = FindObjectBytes(data, objNum);
        if (objStart < 0)
        {
            warnings.Add($"Object {objNum} not found in PDF data.");
            return warnings;
        }

        string objText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));

        if (!objText.Contains(PdfKeys.FtSig, StringComparison.Ordinal) &&
            !objText.Contains(PdfKeys.FtSigNoSpace, StringComparison.Ordinal))
        {
            warnings.Add($"Object {objNum}: missing /FT /Sig (not a signature field).");
        }

        // Check /V reference
        int vIdx = objText.IndexOf("/V ", StringComparison.Ordinal);
        if (vIdx >= 0)
        {
            string afterV = objText[(vIdx + 3)..].TrimStart();
            // Extract object number from "N 0 R"
            int refObjNum = 0;
            int pos = 0;
            while (pos < afterV.Length && char.IsDigit(afterV[pos]))
            {
                refObjNum = refObjNum * 10 + (afterV[pos++] - '0');
            }

            if (refObjNum > 0)
            {
                var (vStart, vEnd) = FindObjectBytes(data, refObjNum);
                if (vStart < 0)
                {
                    warnings.Add($"Object {objNum}: /V references object {refObjNum} which does not exist.");
                }
                else
                {
                    string vObj = Encoding.Latin1.GetString(data.Slice(vStart, vEnd - vStart));
                    if (!vObj.Contains(PdfKeys.TypeSig, StringComparison.Ordinal) &&
                        !vObj.Contains(PdfKeys.TypeSigNoSpace, StringComparison.Ordinal))
                    {
                        warnings.Add($"Object {objNum}: /V references object {refObjNum} which is not a /Type /Sig dictionary.");
                    }
                }
            }
        }

        return warnings;
    }

    /// <summary>
    /// Validates AcroForm /Fields integrity by checking that all referenced objects
    /// exist in the PDF data (§12.7.3). Returns a list of warnings for orphaned references.
    /// </summary>
    public static List<string> ValidateAcroFormFields(ReadOnlySpan<byte> data, List<string> fieldRefs)
    {
        var warnings = new List<string>();
        foreach (string fieldRef in fieldRefs)
        {
            // Parse "N 0 R" → extract N
            string[] parts = fieldRef.Split(' ');
            if (parts.Length < 1 || !int.TryParse(parts[0], out int objNum))
            {
                warnings.Add($"Invalid field reference format: '{fieldRef}'.");
                continue;
            }

            var (objStart, _) = FindObjectBytes(data, objNum);
            if (objStart < 0)
            {
                warnings.Add($"AcroForm /Fields references object {objNum} which does not exist (orphaned reference).");
            }
        }

        return warnings;
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    internal static int FindTrailerSize(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> sizeToken = "/Size "u8;
        int tokenPos = data.LastIndexOf(sizeToken);
        if (tokenPos < 0)
        {
            return 10;
        }

        int cursor = tokenPos + sizeToken.Length;
        int sizeValue = 0;
        while (cursor < data.Length && data[cursor] >= (byte)'0' && data[cursor] <= (byte)'9')
        {
            if (sizeValue > int.MaxValue / 10)
            {
                return 10;
            }

            sizeValue = sizeValue * 10 + (data[cursor++] - '0');
        }

        return sizeValue <= 0 ? 10 : sizeValue;
    }

    internal static int FindHighestObjectNumber(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> objMarker = " 0 obj"u8;
        int highest = 0;
        int pos = 0;

        while (pos < data.Length)
        {
            int idx = data[pos..].IndexOf(objMarker);
            if (idx < 0)
            {
                break;
            }

            int absPos = pos + idx;
            int numEnd = absPos;
            int numStart = numEnd - 1;
            while (numStart >= 0 && data[numStart] >= (byte)'0' && data[numStart] <= (byte)'9')
            {
                numStart--;
            }
            numStart++;

            if (numStart < numEnd)
            {
                int objNum = 0;
                for (int i = numStart; i < numEnd; i++)
                {
                    if (objNum > int.MaxValue / 10)
                    {
                        break;
                    }

                    objNum = objNum * 10 + (data[i] - '0');
                }
                if (objNum > highest)
                {
                    highest = objNum;
                }
            }

            pos = absPos + objMarker.Length;
        }

        return highest;
    }

    private static int FindPageTypeToken(ReadOnlySpan<byte> data, int startPos)
    {
        ReadOnlySpan<byte> token = "/Type /Page"u8;
        ReadOnlySpan<byte> tokenNoSpace = "/Type/Page"u8;

        int pos = startPos;
        while (pos < data.Length)
        {
            ReadOnlySpan<byte> slice = data.Slice(pos);
            int found = slice.IndexOf(token);
            int tokenLen = token.Length;

            if (found < 0)
            {
                found = slice.IndexOf(tokenNoSpace);
                tokenLen = tokenNoSpace.Length;
            }

            if (found < 0)
            {
                return -1;
            }

            int absolutePos = pos + found;
            int afterToken = absolutePos + tokenLen;

            if (afterToken < data.Length && data[afterToken] == (byte)'s')
            {
                pos = afterToken;
                continue;
            }

            return absolutePos;
        }

        return -1;
    }

    private static int FindObjNumBefore(ReadOnlySpan<byte> data, int beforePos)
    {
        int windowStart = Math.Max(0, beforePos - 64);
        ReadOnlySpan<byte> window = data.Slice(windowStart, beforePos - windowStart);

        ReadOnlySpan<byte> objToken = " obj"u8;
        int objTokenPos = window.LastIndexOf(objToken);
        if (objTokenPos < 2)
        {
            return 0;
        }

        int cursor = objTokenPos - 1;
        while (cursor >= 0 && (window[cursor] == (byte)' ' || window[cursor] == (byte)'\r' || window[cursor] == (byte)'\n'))
        {
            cursor--;
        }
        while (cursor >= 0 && window[cursor] >= (byte)'0' && window[cursor] <= (byte)'9')
        {
            cursor--;
        }
        while (cursor >= 0 && (window[cursor] == (byte)' ' || window[cursor] == (byte)'\r' || window[cursor] == (byte)'\n'))
        {
            cursor--;
        }

        int objNumEnd = cursor + 1;
        while (cursor >= 0 && window[cursor] >= (byte)'0' && window[cursor] <= (byte)'9')
        {
            cursor--;
        }
        int objNumStart = cursor + 1;

        if (objNumStart >= objNumEnd)
        {
            return 0;
        }

        int objNum = 0;
        for (int i = objNumStart; i < objNumEnd; i++)
        {
            if (objNum > int.MaxValue / 10)
            {
                return 0;
            }

            objNum = objNum * 10 + (window[i] - '0');
        }

        return objNum;
    }

    private static float ExtractBoxWidth(string text, string boxName)
    {
        int idx = text.LastIndexOf(boxName, StringComparison.Ordinal);
        if (idx < 0)
        {
            return 0f;
        }

        int open = text.IndexOf('[', idx);
        int close = text.IndexOf(']', idx);
        if (open < 0 || close < 0 || close <= open)
        {
            return 0f;
        }

        string[] parts = text.Substring(open + 1, close - open - 1).Trim()
            .Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 4
            && float.TryParse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture, out float llx)
            && float.TryParse(parts[2], NumberStyles.Float, CultureInfo.InvariantCulture, out float urx))
        {
            return urx - llx;
        }

        return 0f;
    }

    private static float ExtractBoxHeight(string text, string boxName)
    {
        int idx = text.LastIndexOf(boxName, StringComparison.Ordinal);
        if (idx < 0)
        {
            return 0f;
        }

        int open = text.IndexOf('[', idx);
        int close = text.IndexOf(']', idx);
        if (open < 0 || close < 0 || close <= open)
        {
            return 0f;
        }

        string[] parts = text.Substring(open + 1, close - open - 1).Trim()
            .Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 4
            && float.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out float lly)
            && float.TryParse(parts[3], NumberStyles.Float, CultureInfo.InvariantCulture, out float ury))
        {
            return ury - lly;
        }

        return 0f;
    }

    /// <summary>
    /// Follows /Parent chain to find inherited /CropBox or /MediaBox width (§8.3.2.1).
    /// </summary>
    private static float ResolveInheritedBoxWidth(ReadOnlySpan<byte> data, string pageDict)
    {
        int parentObjNum = ExtractIntValue(pageDict, "/Parent");
        if (parentObjNum <= 0)
        {
            return 0f;
        }

        for (int depth = 0; depth < 10; depth++)
        {
            var (objStart, objEnd) = FindObjectBytes(data, parentObjNum);
            if (objStart < 0)
            {
                break;
            }

            string parentText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));

            float w = ExtractBoxWidth(parentText, "/CropBox");
            if (w > 0)
            {
                return w;
            }

            w = ExtractBoxWidth(parentText, "/MediaBox");
            if (w > 0)
            {
                return w;
            }

            parentObjNum = ExtractIntValue(parentText, "/Parent");
            if (parentObjNum <= 0)
            {
                break;
            }
        }

        return 0f;
    }

    /// <summary>
    /// Follows /Parent chain to find inherited /CropBox or /MediaBox height (§8.3.2.1).
    /// </summary>
    private static float ResolveInheritedBoxHeight(ReadOnlySpan<byte> data, string pageDict)
    {
        int parentObjNum = ExtractIntValue(pageDict, "/Parent");
        if (parentObjNum <= 0)
        {
            return 0f;
        }

        for (int depth = 0; depth < 10; depth++)
        {
            var (objStart, objEnd) = FindObjectBytes(data, parentObjNum);
            if (objStart < 0)
            {
                break;
            }

            string parentText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));

            float h = ExtractBoxHeight(parentText, "/CropBox");
            if (h > 0)
            {
                return h;
            }

            h = ExtractBoxHeight(parentText, "/MediaBox");
            if (h > 0)
            {
                return h;
            }

            parentObjNum = ExtractIntValue(parentText, "/Parent");
            if (parentObjNum <= 0)
            {
                break;
            }
        }

        return 0f;
    }
    /// <summary>
    /// For indirect references like "/Parent 5 0 R", returns just the object number (5).
    /// </summary>
    private static int ExtractIntValue(string text, string key)
    {
        int idx = text.IndexOf(key, StringComparison.Ordinal);
        if (idx < 0)
        {
            return 0;
        }

        int pos = idx + key.Length;
        while (pos < text.Length && (text[pos] == ' ' || text[pos] == '\n' || text[pos] == '\r'))
        {
            pos++;
        }

        int result = 0;
        bool negative = false;
        if (pos < text.Length && text[pos] == '-')
        {
            negative = true;
            pos++;
        }

        while (pos < text.Length && char.IsDigit(text[pos]))
        {
            result = result * 10 + (text[pos] - '0');
            pos++;
        }

        return negative ? -result : result;
    }

    private static int NormalizeRotation(int degrees)
    {
        int r = degrees % 360;
        if (r < 0)
        {
            r += 360;
        }

        return r;
    }

    /// <summary>
    /// Finds an existing empty signature field by name (/T value) and returns its object number.
    /// An empty signature field has /FT /Sig and either no /V entry or /V that is null.
    /// Returns -1 if not found, throws if the field is already signed.
    /// </summary>
    public static int FindEmptySignatureField(ReadOnlySpan<byte> data, string fieldName)
    {
        // Scan for /FT /Sig objects that match the field name
        string text = Encoding.Latin1.GetString(data);

        int pos = 0;
        while (pos < text.Length)
        {
            int ftPos = text.IndexOf(PdfKeys.FtSig, pos, StringComparison.Ordinal);
            if (ftPos < 0)
            {
                break;
            }

            // Find the enclosing object boundaries
            int objStart = text.LastIndexOf(" 0 obj", ftPos, StringComparison.Ordinal);
            int objEnd = text.IndexOf("endobj", ftPos, StringComparison.Ordinal);
            if (objStart < 0 || objEnd < 0)
            {
                pos = ftPos + 8;
                continue;
            }

            string fullObj = text.Substring(Math.Max(0, objStart - 20), objEnd - Math.Max(0, objStart - 20) + 6);

            // Compare /T with the requested name, decoding literal, hexadecimal,
            // and UTF-16 forms with the shared text-string decoder.
            string? tValue = PdfStructureReader.ExtractPdfString(Encoding.Latin1.GetBytes(fullObj), "/T"u8);
            if (!string.Equals(tValue, fieldName, StringComparison.Ordinal))
            {
                pos = ftPos + 8;
                continue;
            }

            // Parse the object number
            int lineStart = text.LastIndexOf('\n', Math.Max(0, objStart - 1)) + 1;
            string beforeObj = text.Substring(lineStart, objStart + 6 - lineStart);
            int spaceIdx = beforeObj.IndexOf(' ');
            if (spaceIdx > 0 && int.TryParse(beforeObj.AsSpan(0, spaceIdx), out int objNum))
            {
                // Check if /V references an object (signed) — null, names, and
                // literal/hexadecimal strings (including empty ones) are empty fields.
                int vKeyPos = FindTopLevelKey(fullObj, "/V");
                if (vKeyPos >= 0)
                {
                    int cursor = vKeyPos + 2;
                    while (cursor < fullObj.Length && IsPdfWhitespaceChar(fullObj[cursor]))
                    {
                        cursor++;
                    }

                    if (cursor < fullObj.Length && IsAsciiDigit(fullObj[cursor]))
                    {
                        // /V followed by an object reference means it's signed
                        throw new InvalidOperationException(
                            $"Signature field '{fieldName}' is already signed (has /V value).");
                    }
                }

                return objNum; // /V absent or empty value — empty field
            }

            pos = ftPos + 8;
        }

        return -1;
    }

    /// <summary>
    /// Extracts a PDF object's dictionary content from a compressed Object Stream (ObjStm).
    /// Returns the dictionary text (e.g. "&lt;&lt; /Type /Catalog /Pages 2 0 R ... &gt;&gt;"), or null if not found.
    /// Used as a fallback when <see cref="FindObjectBytes"/> cannot locate the object in the file body
    /// because it's stored in a compressed ObjStm (common with iText, Adobe, and other modern PDF generators).
    /// </summary>
    /// <param name="data">The full PDF data.</param>
    /// <param name="targetObjNum">The object number to search for in ObjStm streams.</param>
    public static string? ExtractObjectFromObjStm(ReadOnlySpan<byte> data, int targetObjNum)
    {
        ReadOnlySpan<byte> objStmMarker1 = "/Type /ObjStm"u8;
        ReadOnlySpan<byte> objStmMarker2 = "/Type/ObjStm"u8;
        ReadOnlySpan<byte> streamMarker = "stream"u8;
        // In incremental updates, multiple ObjStm objects may contain the same target object.
        // The LAST occurrence is the most recent revision — keep scanning instead of returning early.
        string? latestContent = null;

        int searchPos = 0;
        while (searchPos < data.Length)
        {
            int pos1 = data[searchPos..].IndexOf(objStmMarker1);
            int pos2 = data[searchPos..].IndexOf(objStmMarker2);
            int matchOffset;
            if (pos1 >= 0 && pos2 >= 0)
            {
                matchOffset = Math.Min(pos1, pos2);
            }
            else if (pos1 >= 0)
            {
                matchOffset = pos1;
            }
            else if (pos2 >= 0)
            {
                matchOffset = pos2;
            }
            else
            {
                break;
            }

            int absolutePos = searchPos + matchOffset;
            searchPos = absolutePos + 1;

            int objStart = FindObjStartBefore(data, absolutePos);
            if (objStart < 0)
            {
                continue;
            }

            int streamKeyPos = PdfStructureReader.IndexOf(data[objStart..], streamMarker, 0);
            if (streamKeyPos < 0)
            {
                continue;
            }

            ReadOnlySpan<byte> dictRegion = data.Slice(objStart, streamKeyPos);

            int nPos = PdfStructureReader.IndexOf(dictRegion, "/N "u8, 0);
            int firstPos = PdfStructureReader.IndexOf(dictRegion, "/First "u8, 0);
            if (nPos < 0 || firstPos < 0)
            {
                continue;
            }

            if (!PdfStructureReader.TryParseDecimalLong(dictRegion, nPos + 3, out long objCount, out _))
            {
                continue;
            }

            if (!PdfStructureReader.TryParseDecimalLong(dictRegion, firstPos + 7, out long firstObjDataOffset, out _))
            {
                continue;
            }

            byte[] decompressed;
            try
            {
                ReadOnlySpan<byte> rawStream = PdfStructureReader.ExtractStreamBytes(data, objStart, dictRegion);
                if (rawStream.IsEmpty)
                {
                    continue;
                }

                decompressed = PdfStructureReader.ApplyStreamFilters(rawStream, dictRegion);
                if (decompressed.Length == 0)
                {
                    continue;
                }
            }
            catch
            {
                continue;
            }

            var objOffsets = new List<(int ObjNum, int Offset)>();
            int headerPos = 0;
            for (int i = 0; i < (int)objCount && headerPos < decompressed.Length; i++)
            {
                headerPos = PdfStructureReader.SkipWhitespace(decompressed, headerPos);
                if (!PdfStructureReader.TryParseDecimalLong(decompressed, headerPos, out long num, out headerPos))
                {
                    break;
                }

                headerPos = PdfStructureReader.SkipWhitespace(decompressed, headerPos);
                if (!PdfStructureReader.TryParseDecimalLong(decompressed, headerPos, out long off, out headerPos))
                {
                    break;
                }

                objOffsets.Add(((int)num, (int)off));
            }

            int targetIdx = -1;
            for (int i = 0; i < objOffsets.Count; i++)
            {
                if (objOffsets[i].ObjNum == targetObjNum)
                {
                    targetIdx = i;
                    break;
                }
            }

            if (targetIdx < 0)
            {
                continue;
            }

            int dataStart = (int)firstObjDataOffset + objOffsets[targetIdx].Offset;
            int dataEnd = (targetIdx + 1 < objOffsets.Count)
                ? (int)firstObjDataOffset + objOffsets[targetIdx + 1].Offset
                : decompressed.Length;

            if (dataStart < 0 || dataStart >= decompressed.Length)
            {
                continue;
            }

            dataEnd = Math.Min(dataEnd, decompressed.Length);

            string content = Encoding.Latin1.GetString(decompressed.AsSpan(dataStart, dataEnd - dataStart)).Trim();
            if (content.Length > 0)
            {
                latestContent = content;
            }
        }

        return latestContent;
    }

    /// <summary>
    /// Extracts /Fields references from an AcroForm object stored in a compressed Object Stream
    /// (PDF 1.5+, ObjStm). Used as a fallback when <see cref="FindObjectBytes"/> cannot locate
    /// the AcroForm by text search (common with iText, Adobe, and other modern PDF generators).
    /// </summary>
    /// <param name="data">The full PDF data.</param>
    /// <param name="acroFormObjNum">The AcroForm object number to search for.</param>
    /// <returns>
    /// A list of indirect references (e.g., "5 0 R") found in the AcroForm's /Fields array,
    /// or an empty list if the object cannot be found or decompressed.
    /// </returns>
    public static List<string> ExtractFieldsFromCompressedAcroForm(ReadOnlySpan<byte> data, int acroFormObjNum)
    {
        // Scan for all Object Stream (ObjStm) objects in the PDF.
        // ObjStm objects are always stored as regular (type 1) objects — they cannot be nested.
        // In incremental updates, multiple ObjStm objects may contain the same AcroForm obj number
        // with progressively more /Fields entries. We need the LAST (most recent) version.
        ReadOnlySpan<byte> objStmMarker1 = "/Type /ObjStm"u8;
        ReadOnlySpan<byte> objStmMarker2 = "/Type/ObjStm"u8;
        ReadOnlySpan<byte> streamMarker = "stream"u8;
        List<string> latestFields = [];

        int searchPos = 0;
        while (searchPos < data.Length)
        {
            // Find the next ObjStm marker
            int pos1 = data[searchPos..].IndexOf(objStmMarker1);
            int pos2 = data[searchPos..].IndexOf(objStmMarker2);
            int matchOffset;
            if (pos1 >= 0 && pos2 >= 0)
            {
                matchOffset = Math.Min(pos1, pos2);
            }
            else if (pos1 >= 0)
            {
                matchOffset = pos1;
            }
            else if (pos2 >= 0)
            {
                matchOffset = pos2;
            }
            else
            {
                break;
            }

            int absolutePos = searchPos + matchOffset;
            searchPos = absolutePos + 1;

            // Walk backwards to find the start of this object ("N 0 obj")
            int objStart = FindObjStartBefore(data, absolutePos);
            if (objStart < 0)
            {
                continue;
            }

            // Find "stream" keyword to delimit the dictionary region
            int streamKeyPos = PdfStructureReader.IndexOf(data[objStart..], streamMarker, 0);
            if (streamKeyPos < 0)
            {
                continue;
            }

            ReadOnlySpan<byte> dictRegion = data.Slice(objStart, streamKeyPos);

            // Parse /N (number of objects) and /First (byte offset of first object data)
            int nPos = PdfStructureReader.IndexOf(dictRegion, "/N "u8, 0);
            int firstPos = PdfStructureReader.IndexOf(dictRegion, "/First "u8, 0);
            if (nPos < 0 || firstPos < 0)
            {
                continue;
            }

            if (!PdfStructureReader.TryParseDecimalLong(dictRegion, nPos + 3, out long objCount, out _))
            {
                continue;
            }

            if (!PdfStructureReader.TryParseDecimalLong(dictRegion, firstPos + 7, out long firstObjDataOffset, out _))
            {
                continue;
            }

            // Extract and decompress the stream
            byte[] decompressed;
            try
            {
                ReadOnlySpan<byte> rawStream = PdfStructureReader.ExtractStreamBytes(data, objStart, dictRegion);
                if (rawStream.IsEmpty)
                {
                    continue;
                }

                decompressed = PdfStructureReader.ApplyStreamFilters(rawStream, dictRegion);
                if (decompressed.Length == 0)
                {
                    continue;
                }
            }
            catch
            {
                continue;
            }

            // Parse the ObjStm header: N pairs of (objectNumber, byteOffset)
            // Offsets are relative to /First
            var objOffsets = new List<(int ObjNum, int Offset)>();
            int headerPos = 0;
            for (int i = 0; i < (int)objCount && headerPos < decompressed.Length; i++)
            {
                headerPos = PdfStructureReader.SkipWhitespace(decompressed, headerPos);
                if (!PdfStructureReader.TryParseDecimalLong(decompressed, headerPos, out long num, out headerPos))
                {
                    break;
                }

                headerPos = PdfStructureReader.SkipWhitespace(decompressed, headerPos);
                if (!PdfStructureReader.TryParseDecimalLong(decompressed, headerPos, out long off, out headerPos))
                {
                    break;
                }

                objOffsets.Add(((int)num, (int)off));
            }

            // Check if our target AcroForm object is in this ObjStm
            int targetIdx = -1;
            for (int i = 0; i < objOffsets.Count; i++)
            {
                if (objOffsets[i].ObjNum == acroFormObjNum)
                {
                    targetIdx = i;
                    break;
                }
            }

            if (targetIdx < 0)
            {
                continue;
            }

            // Extract the AcroForm dict content from the decompressed data
            int dataStart = (int)firstObjDataOffset + objOffsets[targetIdx].Offset;
            int dataEnd = (targetIdx + 1 < objOffsets.Count)
                ? (int)firstObjDataOffset + objOffsets[targetIdx + 1].Offset
                : decompressed.Length;

            if (dataStart < 0 || dataStart >= decompressed.Length)
            {
                continue;
            }

            dataEnd = Math.Min(dataEnd, decompressed.Length);

            string acroFormContent = Encoding.Latin1.GetString(decompressed.AsSpan(dataStart, dataEnd - dataStart));
            var fields = ParseFieldsArray(acroFormContent);
            if (fields.Count > 0)
            {
                // Don't return immediately — keep scanning for later ObjStm revisions
                // that may contain a more complete /Fields array (incremental updates
                // create new ObjStm objects with the same AcroForm object number).
                latestFields = fields;
            }
        }

        return latestFields;
    }

    /// <summary>
    /// Extracts the /ID array from the last trailer in the PDF (e.g. /ID [&lt;abc&gt; &lt;def&gt;]).
    /// Returns the full "/ID [...]" string suitable for inclusion in a new trailer, or null if not found.
    /// Per ISO 32000 §14.4, incremental updates must preserve the document identity.
    /// </summary>
    public static string? FindTrailerId(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> idToken = "/ID"u8;
        int tokenPos = data.LastIndexOf(idToken);
        if (tokenPos < 0)
        {
            return null;
        }

        // Ensure it's /ID followed by whitespace or [, not /IDSomething
        int afterToken = tokenPos + idToken.Length;
        if (afterToken < data.Length && data[afterToken] != (byte)' '
            && data[afterToken] != (byte)'\n' && data[afterToken] != (byte)'\r'
            && data[afterToken] != (byte)'[')
        {
            return null;
        }

        // Find the opening [
        int cursor = afterToken;
        while (cursor < data.Length && data[cursor] != (byte)'[')
        {
            cursor++;
            if (cursor - afterToken > 20)
            {
                return null;
            }
        }

        if (cursor >= data.Length)
        {
            return null;
        }

        // Find the matching ]
        int bracketStart = cursor;
        int depth = 0;
        for (int i = bracketStart; i < data.Length && i - bracketStart < 200; i++)
        {
            if (data[i] == (byte)'[')
            {
                depth++;
            }
            else if (data[i] == (byte)']')
            {
                depth--;
                if (depth == 0)
                {
                    string idArray = Encoding.Latin1.GetString(data.Slice(bracketStart, i - bracketStart + 1));
                    return $"/ID {idArray}";
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Extracts the /Info reference from the last trailer (e.g. "/Info 5 0 R").
    /// Returns the full "/Info N 0 R" string, or null if not found.
    /// </summary>
    public static string? FindTrailerInfo(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> infoToken = "/Info "u8;
        int tokenPos = data.LastIndexOf(infoToken);
        if (tokenPos < 0)
        {
            return null;
        }

        int cursor = tokenPos + infoToken.Length;
        // Skip whitespace
        while (cursor < data.Length && (data[cursor] == (byte)' ' || data[cursor] == (byte)'\n' || data[cursor] == (byte)'\r'))
        {
            cursor++;
        }

        // Parse object number
        int objNum = 0;
        while (cursor < data.Length && data[cursor] >= (byte)'0' && data[cursor] <= (byte)'9')
        {
            if (objNum > int.MaxValue / 10)
            {
                return null;
            }

            objNum = objNum * 10 + (data[cursor++] - '0');
        }

        if (objNum <= 0)
        {
            return null;
        }

        // Expect " 0 R"
        int remaining = data.Length - cursor;
        if (remaining < 4)
        {
            return null;
        }

        // Skip space before generation number
        while (cursor < data.Length && data[cursor] == (byte)' ')
        {
            cursor++;
        }

        // Parse generation number (should be 0)
        int genNum = 0;
        while (cursor < data.Length && data[cursor] >= (byte)'0' && data[cursor] <= (byte)'9')
        {
            if (genNum > int.MaxValue / 10)
            {
                return null;
            }

            genNum = genNum * 10 + (data[cursor++] - '0');
        }

        // Skip space before R
        while (cursor < data.Length && data[cursor] == (byte)' ')
        {
            cursor++;
        }

        if (cursor < data.Length && data[cursor] == (byte)'R')
        {
            return $"/Info {objNum} {genNum} R";
        }

        return null;
    }

    /// <summary>
    /// Walks backwards from a given position to find the start of a PDF object definition (N 0 obj).
    /// Returns the byte offset of the object start, or -1 if not found.
    /// </summary>
    private static int FindObjStartBefore(ReadOnlySpan<byte> data, int fromPos)
    {
        // Search backwards for "obj" preceded by "N 0 "
        ReadOnlySpan<byte> objToken = " 0 obj"u8;
        int scanStart = Math.Max(0, fromPos - 200);
        int region = fromPos - scanStart;
        if (region <= 0)
        {
            return -1;
        }

        ReadOnlySpan<byte> slice = data.Slice(scanStart, region);
        int lastObjPos = slice.LastIndexOf(objToken);
        if (lastObjPos < 0)
        {
            return -1;
        }

        // Walk backwards to find the start of the object number
        int numEnd = lastObjPos;
        int numStart = numEnd - 1;
        while (numStart >= 0 && data[scanStart + numStart] >= (byte)'0' && data[scanStart + numStart] <= (byte)'9')
        {
            numStart--;
        }

        numStart++;

        if (numStart >= numEnd)
        {
            return -1;
        }

        // The object starts at the first digit of the object number
        int result = scanStart + numStart;

        // Validate it's preceded by whitespace or line start
        if (result > 0 && data[result - 1] != (byte)'\n' && data[result - 1] != (byte)'\r' && data[result - 1] != (byte)' ')
        {
            return -1;
        }

        return result;
    }
}
