﻿
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.RegularExpressions;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities;

[TestClass, ExcludeFromCodeCoverage]
public class RegexPatternTests
{
    private const string Id = nameof(Id);
    private const string Name = nameof(Name);
    private const string Label = "a test secret";

    [TestMethod]
    public void RegexPattern_Equals_ReturnsTrue_WhenPatternsAreEqual()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsFalse_WhenPatternsDiffer()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "def");

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsFalse_WhenIdsDiffer()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");
        var secret2 = new RegexPattern($"{Guid.NewGuid()}", Name, Label, DetectionMetadata.Identifiable, "abc");

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsFalse_WhenNamesDiffer()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");
        var secret2 = new RegexPattern(Id, $"{Guid.NewGuid()}", Label, DetectionMetadata.Identifiable, "abc");

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsFalse_WhenDetectionMetadataDiffers()
    {
        // Should regexes in fact be relevant to object equality? For a consistent
        // rule id and name, the metadata should be fixed/consistent. If we have
        // two instances that only differ in this data, one of them is wrong.

        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.ObsoleteFormat, "abc");

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsTrue_WhenSniffLiteralsAreEqual()
    {
        // Arrange
        var signatures = new HashSet<string>(new[] { "sniff" });
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", signatures: signatures);
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", signatures: signatures);

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsTrue_WhenSniffLiteralsDiffer()
    {
        // Arrange
        var sniffLiterals = new HashSet<string>(new[] { "sniff" });
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", signatures: sniffLiterals);
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", signatures: new HashSet<string>());

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsFalse(result);
    }


    [TestMethod]
    public void RegexPattern_Equals_ReturnsTrue_WhenRotationPeriodsAreEqual()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", TimeSpan.FromSeconds(15));
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", TimeSpan.FromSeconds(15));

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsFalse_WhenRotationPeriodsDiffer()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", TimeSpan.FromSeconds(15));
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", TimeSpan.FromSeconds(300));

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsTrue_WhenRegexOptionsAreEqual()
    {
        // Arrange
        RegexOptions regexOptions = RegexOptions.IgnoreCase;
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", regexOptions: regexOptions);
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", regexOptions: regexOptions);

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsFalse_WhenRegexOptionsDiffer()
    {
        // Arrange
        RegexOptions regexOptions = RegexOptions.IgnoreCase;
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", regexOptions: regexOptions);
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", regexOptions: RegexOptions.IgnorePatternWhitespace);

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsTrue_WhenLabelsAreEqual()
    {
        var sampleGenerator = () => { return new[] { "abc" }; };

        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", sampleGenerator: sampleGenerator);
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", sampleGenerator: sampleGenerator);

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsTrue_WhenLabelsDiffer()
    {

        // Arrange
        var secret1 = new RegexPattern(Id, Name, $"{Guid.NewGuid()}", DetectionMetadata.Identifiable, "abc");
        var secret2 = new RegexPattern(Id, Name, $"{Guid.NewGuid()}", DetectionMetadata.Identifiable, "abc");

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsTrue_WhenSampleGeneratorsAreEqual()
    {
        var sampleGenerator = () => { return new[] { "abc" }; };

        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", sampleGenerator: sampleGenerator);
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", sampleGenerator: sampleGenerator);

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsTrue_WhenSampleGeneratorsDiffer()
    {
        var sampleGenerator1 = () => { return new[] { "abc" }; };
        var sampleGenerator2 = () => { return new[] { "abcabc" }; };

        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", sampleGenerator: sampleGenerator1);
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", sampleGenerator: sampleGenerator1);

        // Act
        var result = secret1.Equals(secret2);

        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void RegexPattern_Equals_ReturnsFalse_WhenComparedToNull()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");

        // Act
        var result = secret1.Equals(null);

        // Assert
        Assert.IsFalse(result);
    }


    [TestMethod]
    public void RegexPattern_GetHashCode_ReturnsUniqueValue_WhenPatternsDiffer()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "def");

        // Act
        var hashCodeDiffers = secret1.GetHashCode() != secret2.GetHashCode();

        // Assert
        Assert.IsTrue(hashCodeDiffers);
    }

    [TestMethod]
    public void RegexPattern_GetHashCode_ReturnsUniqueValue_WhenIdsDiffer()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");
        var secret2 = new RegexPattern($"{Guid.NewGuid()}", Label, Name, DetectionMetadata.Identifiable, "abc");
        var set = new HashSet<RegexPattern>(new[] { secret1 });

        // Act
        var hashCodeDiffers = secret1.GetHashCode() != secret2.GetHashCode();

        // Assert
        Assert.IsTrue(hashCodeDiffers);
    }

    [TestMethod]
    public void RegexPattern_GetHashCode_ReturnsUniqueValue_WhenNamesDiffer()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");
        var secret2 = new RegexPattern(Id, $"{Guid.NewGuid()}", Label, DetectionMetadata.Identifiable, "abc");
        var set = new HashSet<RegexPattern>(new[] { secret1 });

        // Act
        var hashCodeDiffers = secret1.GetHashCode() != secret2.GetHashCode();

        // Assert
        Assert.IsTrue(hashCodeDiffers);
    }

    [TestMethod]
    public void RegexPattern_GetHashCode_ReturnsUniqueValue_WhenRotationPeriodsDiffer()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", TimeSpan.FromMilliseconds(10));
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", TimeSpan.FromHours(24));

        // Act
        var hashCodeDiffers = secret1.GetHashCode() != secret2.GetHashCode();

        // Assert
        Assert.IsTrue(hashCodeDiffers);
    }

    [TestMethod]
    public void RegexPattern_GetHashCode_ReturnsUniqueValue_WhenDetectionMetadataDiffers()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.FixedSignature, "abc");
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.ObsoleteFormat, "abc");

        // Act
        var hashCodeDiffers = secret1.GetHashCode() != secret2.GetHashCode();

        // Assert
        Assert.IsTrue(hashCodeDiffers);
    }

    [TestMethod]
    public void RegexPattern_GetHashCode_ReturnsUniqueValue_WhenSniffLiteralsDiffer()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", signatures: new HashSet<string>(new[] { "sniff1" }));
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", signatures: new HashSet<string>(new[] { "sniff2" }));

        // Act
        var hashCodeDiffers = secret1.GetHashCode() != secret2.GetHashCode();

        // Assert
        Assert.IsTrue(hashCodeDiffers);
    }

    [TestMethod]
    public void RegexPattern_GetHashCode_ReturnsUniqueValue_WhenRegexOptionsDiffer()
    {
        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", regexOptions: RegexOptions.Multiline);
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", regexOptions: RegexOptions.IgnoreCase);

        var set = new HashSet<RegexPattern>(new[] { secret1 });

        // Act
        var hashCodeDiffers = secret1.GetHashCode() != secret2.GetHashCode();

        // Assert
        Assert.IsTrue(hashCodeDiffers);
    }

    [TestMethod]
    public void RegexPattern_GetHashCode_ReturnsConsistentValue_WhenSampleGeneratorsDiffer()
    {
        var sampleGenerator1 = () => { return new[] { "abc" }; };
        var sampleGenerator2 = () => { return new[] { "abcabc" }; };

        // Arrange
        var secret1 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", sampleGenerator: sampleGenerator1);
        var secret2 = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc", sampleGenerator: sampleGenerator2);

        var set = new HashSet<RegexPattern>(new[] { secret1 });

        // Act
        var hashCodeDiffers = secret1.GetHashCode() != secret2.GetHashCode();

        // Assert
        Assert.IsFalse(hashCodeDiffers);
    }

    [TestMethod]
    public void RegexPattern_GetHashCode_ReturnsConsistentValue_WhenLabelsDiffer()
    {
        var sampleGenerator1 = () => { return new[] { "abc" }; };
        var sampleGenerator2 = () => { return new[] { "abcabc" }; };

        // Arrange
        var secret1 = new RegexPattern(Id, Name, $"{Guid.NewGuid()}", DetectionMetadata.Identifiable, "abc", sampleGenerator: sampleGenerator1);
        var secret2 = new RegexPattern(Id, Name, $"{Guid.NewGuid()}", DetectionMetadata.Identifiable, "abc", sampleGenerator: sampleGenerator2);

        var set = new HashSet<RegexPattern>(new[] { secret1 });

        // Act
        var hashCodeDiffers = secret1.GetHashCode() != secret2.GetHashCode();

        // Assert
        Assert.IsFalse(hashCodeDiffers);
    }

    [TestMethod]
    public void RegexPattern_GetHashCode_ReturnsConsistentTelemetry_AcrossDotNetFrameworkVersions()
    {
        // Arrange
        var secret = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "test", regexOptions: RegexOptions.Multiline);

        // Act
        var replacements = secret.GetDetections("test", generateCrossCompanyCorrelatingIds: true);

        // Assert
        Assert.AreEqual(1, actual: replacements.Count());
        var replacement = replacements.First();

        // It is critical that our hashing is consistent across the library's .NET FX
        // and .NET 5.0 versions, so we hard-code this test to ensure things are in sync.
        Assert.AreEqual($"rPHgxCVAOw6CZsT9xXEw", replacement.CrossCompanyCorrelatingId);
        Assert.AreEqual($"{Id}:rPHgxCVAOw6CZsT9xXEw", replacement.RedactionToken);
    }

    [TestMethod]
    public void RegexPatterns_GetDetections_ReturnsEmpty_WhenNoMatchesExist()
    {
        // Arrange
        var secret = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");
        var input = "defdefdef";

        // Act
        var replacements = secret.GetDetections(input, generateCrossCompanyCorrelatingIds: true);

        // Assert
        Assert.AreEqual(0, actual: replacements.Count());
    }

    [TestMethod]
    public void RegexPatterns_GetDetections_Returns_RefinedDetection()
    {
        // Arrange
        var secret = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "a(?P<refine>b)c");
        var input = "abc";
        var match = "b";

        // Act
        var detections = secret.GetDetections(input, generateCrossCompanyCorrelatingIds: true);
        Detection detection = detections.First();
        var redactionToken = $"{Id}:{RegexPattern.GenerateCrossCompanyCorrelatingId(match)}";

        // Assert
        Assert.AreEqual(1, actual: detections.Count());

        Assert.AreEqual(match, actual: input.Substring(detection.Start, detection.Length));
        Assert.AreEqual(redactionToken, actual: detection.RedactionToken);
    }

    [TestMethod]
    public void RegexPatterns_GetDetections_Returns_SecureTelemetryTokenValue_WhenMonikerSpecified()
    {
        // Arrange
        var ruleMoniker = $"{Id}.{Name}";
        var secret = new RegexPattern(Id, Name, Label, DetectionMetadata.Identifiable, "abc");
        var input = "abc";

        var redactionToken = $"{Id}:{RegexPattern.GenerateCrossCompanyCorrelatingId(input)}";

        // Act
        var replacements = secret.GetDetections(input, generateCrossCompanyCorrelatingIds: true);

        // Assert
        Assert.AreEqual(1, actual: replacements.Count());
        Assert.AreEqual(redactionToken, actual: replacements.First().RedactionToken);
    }

    [TestMethod]
    public void RegexPatterns_RaisesArgumentException_OnNullPattern()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            new RegexPattern(Id, Name, Label, DetectionMetadata.HighEntropy, null);
        });
    }

    [TestMethod]
    public void RegexPattern_RegexOptions_NoExplicitArg_UsesDefaults()
    {
        var pattern = new RegexPattern("id", "name", "label", DetectionMetadata.None, ".");
        pattern.RegexOptions.Should().Be(RegexDefaults.DefaultOptions,
                                         because: "no regex options were passed at construction so default opptions should be used");
    }

    [TestMethod]
    public void RegexPattern_RegexOptions_ExplicitNullArg_UsesDefaults()
    {
        var pattern = new RegexPattern("id", "name", "label", DetectionMetadata.None, ".", regexOptions: null);
        pattern.RegexOptions.Should().Be(RegexDefaults.DefaultOptions,
                                         because: "null was passed explicitly which should be equivalent to not passing anything");
    }

    [TestMethod]
    public void RegexPattern_RegexOptions_ExplicitZeroArg_UsesNoOptions()
    {
        var pattern = new RegexPattern("id", "name", "label", DetectionMetadata.None, ".", regexOptions: 0);
        pattern.RegexOptions.Should().Be(RegexOptions.None,
                                         because: "a non-null value of zero was passed explicitly at construction");
    }

    [TestMethod]
    public void RegexPattern_RegexOptions_ExplicitCustomArg_UsesCustomArg()
    {
        var pattern = new RegexPattern(id: "id",
                                       name: "name",
                                       label: "label",
                                       DetectionMetadata.None,
                                       pattern: ".",
                                       regexOptions: RegexOptions.Multiline);

        pattern.RegexOptions.Should().Be(RegexOptions.Multiline,
                                         because: "RegexOptions.Multiline was passed at construction and no other options should be added");
    }

    [TestMethod]
    public void RegexPattern_ExplicitNoRegexOptions_UsesNoOptions()
    {
        var pattern = new RegexPattern(id: "id",
                                       name: "name",
                                       label: "label",
                                       DetectionMetadata.None,
                                       pattern: ".",
                                       regexOptions: 0);

        pattern.RegexOptions.Should().Be(RegexOptions.None,
                                         because: "the default argument was explicitly passed a non-null zero value");
    }
}