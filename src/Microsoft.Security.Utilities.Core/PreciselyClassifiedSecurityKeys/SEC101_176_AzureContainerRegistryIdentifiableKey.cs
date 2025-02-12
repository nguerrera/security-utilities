// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureContainerRegistryIdentifiableKey : IdentifiableKey
    {
        public AzureContainerRegistryIdentifiableKey()
        {
            Id = "SEC101/176";
            Name = nameof(AzureContainerRegistryIdentifiableKey);
            Signatures = IdentifiableMetadata.AzureContainerRegistrySignature.ToSet();
            Pattern = @$"{WellKnownRegexPatterns.PrefixAllBase64}(?<refine>[{WellKnownRegexPatterns.Base64}]{{42}}{RegexNormalizedSignature}[A-D][{WellKnownRegexPatterns.Base64}]{{5}}){WellKnownRegexPatterns.SuffixAllBase64}";
        }

        override public IEnumerable<ulong> ChecksumSeeds { get; } = [ IdentifiableMetadata.AzureContainerRegistryChecksumSeed ];

        public override string Pattern
        {
            get => @$"{WellKnownRegexPatterns.PrefixAllBase64}(?<refine>[{WellKnownRegexPatterns.Base64}]{{42}}{RegexNormalizedSignature}[A-D][{WellKnownRegexPatterns.Base64}]{{5}}){WellKnownRegexPatterns.SuffixAllBase64}";
            protected set => base.Pattern = value;
        }

        override public uint KeyLength => 39;

        public override int CharsToScanBeforeSignature => 42;
        public override int CharsToScanAfterSignature => 6;
    }
}
