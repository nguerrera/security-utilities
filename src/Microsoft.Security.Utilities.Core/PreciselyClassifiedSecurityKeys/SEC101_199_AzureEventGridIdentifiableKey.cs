// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureEventGridIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureEventGridIdentifiableKey()
        {
            Id = "SEC101/199";
            Name = nameof(AzureEventGridIdentifiableKey);
            Signatures = IdentifiableMetadata.AzureEventGridSignature.ToSet();
        }

        public override IEnumerable<ulong> ChecksumSeeds { get; } = new[] { IdentifiableSecrets.VersionTwoChecksumSeed };
    }
}
