using Shouldly;
using SimpleSign.Cli.Rendering;

namespace SimpleSign.Cli.Tests;

public sealed class AppearanceBuilderTests
{
    [Fact]
    public void Build_NonVisible_ReturnsNull()
    {
        var result = AppearanceBuilder.Build(false, null, null, null, null, null, false, false);
        result.ShouldBeNull();
    }

    [Fact]
    public void Build_VisibleAutoPosition_SetsDefaults()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false);

        result.ShouldNotBeNull();
        result.AutoPosition.ShouldBeTrue();
        result.Page.ShouldBe(1);
        result.X.ShouldBe(20f);
        result.Y.ShouldBe(20f);
        result.ShowReason.ShouldBeFalse();
        result.ShowLocation.ShouldBeFalse();
        result.VerificationUrl.ShouldBeNull();
    }

    [Fact]
    public void Build_WithCoordinates_DisablesAutoPosition()
    {
        var result = AppearanceBuilder.Build(true, null, null, 3, 100f, 200f, true, true);

        result.ShouldNotBeNull();
        result.AutoPosition.ShouldBeFalse();
        result.Page.ShouldBe(3);
        result.X.ShouldBe(100f);
        result.Y.ShouldBe(200f);
        result.ShowReason.ShouldBeTrue();
        result.ShowLocation.ShouldBeTrue();
    }

    [Fact]
    public void Build_WithQrUrl_SetsVerificationUrl()
    {
        var result = AppearanceBuilder.Build(true, null, "https://verify.example.com", null, null, null, false, false);

        result.ShouldNotBeNull();
        result.VerificationUrl.ShouldBe("https://verify.example.com");
    }

    [Fact]
    public void Build_WithPngBackground_SetsBackgroundImagePng()
    {
        var tempPng = Path.GetTempFileName() + ".png";
        try
        {
            File.WriteAllBytes(tempPng, [0x89, 0x50, 0x4E, 0x47]);

            var result = AppearanceBuilder.Build(true, tempPng, null, null, null, null, false, false);

            result.ShouldNotBeNull();
            result.BackgroundImagePng.HasValue.ShouldBeTrue();
            result.BackgroundImagePng!.Value.ToArray().ShouldBe([0x89, 0x50, 0x4E, 0x47]);
            result.BackgroundImageJpeg.HasValue.ShouldBeFalse();
        }
        finally
        {
            File.Delete(tempPng);
        }
    }

    [Fact]
    public void Build_WithJpgBackground_SetsBackgroundImageJpeg()
    {
        var tempJpg = Path.GetTempFileName() + ".jpg";
        try
        {
            File.WriteAllBytes(tempJpg, [0xFF, 0xD8, 0xFF, 0xE0]);

            var result = AppearanceBuilder.Build(true, tempJpg, null, null, null, null, false, false);

            result.ShouldNotBeNull();
            result.BackgroundImageJpeg.HasValue.ShouldBeTrue();
            result.BackgroundImageJpeg!.Value.ToArray().ShouldBe([0xFF, 0xD8, 0xFF, 0xE0]);
            result.BackgroundImagePng.HasValue.ShouldBeFalse();
        }
        finally
        {
            File.Delete(tempJpg);
        }
    }

    [Fact]
    public void Build_WithFontSize_SetsCustomFontSize()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false, fontSize: 12f);

        result.ShouldNotBeNull();
        result.CustomFontSize.ShouldBe(12f);
    }

    [Fact]
    public void Build_WithLabelFontSize_SetsCustomLabelFontSize()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false, labelFontSize: 10f);

        result.ShouldNotBeNull();
        result.CustomLabelFontSize.ShouldBe(10f);
    }

    [Fact]
    public void Build_WithTextColor_SetsTextColor()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false, textColor: "0.5,0.5,0.5");

        result.ShouldNotBeNull();
        result.TextColor.ShouldNotBeNull();
        (result.TextColor!.Value.R, result.TextColor!.Value.G, result.TextColor!.Value.B)
            .ShouldBe((0.5f, 0.5f, 0.5f));
    }

    [Fact]
    public void Build_WithFont_SetsBaseFontName()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false, font: "Times-Roman");

        result.ShouldNotBeNull();
        result.BaseFontName.ShouldBe("Times-Roman");
    }

    [Fact]
    public void Build_WithBorderColor_SetsBorderColor()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false,
            borderColor: "0.2,0.2,0.2", borderWidth: 1f);

        result.ShouldNotBeNull();
        result.BorderColor.ShouldNotBeNull();
        (result.BorderColor!.Value.R, result.BorderColor!.Value.G, result.BorderColor!.Value.B)
            .ShouldBe((0.2f, 0.2f, 0.2f));
        result.BorderWidth.ShouldBe(1f);
    }

    [Fact]
    public void Build_WithNoDate_HidesDate()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false, noDate: true);

        result.ShouldNotBeNull();
        result.ShowDate.ShouldBeFalse();
    }

    [Theory]
    [InlineData("0.5,0.5,0.5", 0.5f, 0.5f, 0.5f)]
    [InlineData("1,0,0", 1f, 0f, 0f)]
    [InlineData("0,0,0", 0f, 0f, 0f)]
    [InlineData("0.25,0.5,0.75", 0.25f, 0.5f, 0.75f)]
    public void ParseColor_ValidInput_ReturnsColor(string input, float r, float g, float b)
    {
        var result = AppearanceBuilder.ParseColor(input);
        result.ShouldNotBeNull();
        (result!.Value.R, result!.Value.G, result!.Value.B).ShouldBe((r, g, b));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("1,2")]
    [InlineData("1,2,3,4")]
    [InlineData("abc,def,ghi")]
    public void ParseColor_InvalidInput_ReturnsNull(string? input) =>
        AppearanceBuilder.ParseColor(input).ShouldBeNull();

    [Fact]
    public void ParseColor_OutOfRange_ClampsToZeroOne() =>
        AppearanceBuilder.ParseColor("2,-1,0.5").ShouldBe((1f, 0f, 0.5f));

    [Fact]
    public void AddAeaExtraLines_AddsNameAndMaskedCpf()
    {
        var baseAppearance = AppearanceBuilder.Build(true, null, null, 1, 50f, 60f, true, false);

        var result = AppearanceBuilder.AddAeaExtraLines(baseAppearance, "André Almeida", "12345678901");

        result.ShouldNotBeNull();
        result.ExtraLines.ShouldNotBeNull();
        result.ExtraLines.Count.ShouldBe(2);
        result.ExtraLines[0].ShouldBe("André Almeida");
        result.ExtraLines[1].ShouldBe("CPF: ***.456.789-**");
        result.Page.ShouldBe(1);
        result.X.ShouldBe(50f);
        result.Y.ShouldBe(60f);
        result.AutoPosition.ShouldBeFalse();
    }
}
