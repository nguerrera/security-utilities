﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Security.Utilities
{
    public abstract class IdentifiableKey : RegexPattern, IIdentifiableKey, IHighPerformanceScannableKey
    {
        protected IdentifiableKey(string signature)
        {
            RotationPeriod = TimeSpan.FromDays(365 * 2);
            DetectionMetadata = DetectionMetadata.Identifiable;
            Signatures = new HashSet<string>([signature]);
            ChecksumSeeds = Array.Empty<ulong>();
        }

        // Identifiable key patterns must have exactly one signature.
        internal string Signature => Signatures!.Single();

        public virtual uint KeyLength => 32;

        public virtual bool EncodeForUrl => false;

        public IEnumerable<ulong> ChecksumSeeds { get; protected set; }

#if HIGH_PERFORMANCE_CODEGEN
        IEnumerable<HighPerformancePattern> IHighPerformanceScannableKey.HighPerformancePatterns => HighPerformancePatterns;
        private protected abstract IEnumerable<HighPerformancePattern> HighPerformancePatterns { get; }
#endif

        public override Tuple<string, string>? GetMatchIdAndName(string match)
        {
            foreach (ulong checksumSeed in ChecksumSeeds)
            {
                if (IdentifiableSecrets.ValidateChecksum(match,
                                                         checksumSeed,
                                                         out byte[] bytes))
                {
                    return new Tuple<string, string>(Id, Name);
                }
            }

            return null;
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            foreach (ulong checksumSeed in ChecksumSeeds)
            {
                string alphabet = EncodeForUrl ? WellKnownRegexPatterns.UrlSafeBase64 : WellKnownRegexPatterns.Base64;

                for (int i = 0; i < 5; i++)
                {
                    byte[] bytes = new byte[KeyLength];
                    int encodedLength = Convert.ToBase64String(bytes).Length;
                    string encoded = new string(alphabet[i], encodedLength);
                    Array.Copy(Convert.FromBase64String(encoded), bytes, KeyLength);

                    string key =
                        IdentifiableSecrets.GenerateBase64KeyHelper(checksumSeed,
                                                                    keyLengthInBytes: KeyLength,
                                                                    Signatures!.First(),
                                                                    EncodeForUrl,
                                                                    bytes);

                    yield return key;

                    foreach (string prefix in s_nonInvalidatingPrefixes)
                    {
                        yield return $"{prefix}{key}";
                    }

                    foreach (string suffix in s_nonInvalidatingSuffixes)
                    {
                        yield return $"{key}{suffix}";
                    }
                }
            }
        }

        private static readonly string[] s_nonInvalidatingPrefixes = new[]
        {
            "=",
        };

        private static readonly string[] s_nonInvalidatingSuffixes = new[]
        {
            ";",
        };
    }
}
