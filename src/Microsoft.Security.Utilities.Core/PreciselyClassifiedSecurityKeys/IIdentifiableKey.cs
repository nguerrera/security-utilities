// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public interface IFastScannableKey
    {
        public int CharsToScanBeforeSignature { get; }
        public int CharsToScanAfterSignature { get; }
    }

    public interface IIdentifiableKey : IFastScannableKey
    {
        public string Id { get; }

        public string Name { get; } 
        
        public uint KeyLength { get; }
        
        public bool EncodeForUrl { get; }

        public ISet<string> Signatures { get; }

        public IEnumerable<ulong> ChecksumSeeds { get; }
    }
}