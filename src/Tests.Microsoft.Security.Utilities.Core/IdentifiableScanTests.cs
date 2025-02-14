// Copyright(c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

using FluentAssertions;
using FluentAssertions.Execution;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using IdentifiableScan = Microsoft.Security.Utilities.IdentifiableScan_Managed;

namespace Tests.Microsoft.Security.Utilities.Core
{
    [TestClass, ExcludeFromCodeCoverage]
    public class IdentifiableScanTests
    {
        [TestMethod]
        public void IdentifiableScan_CommonAnnotatedSecurityKey_PrefixOrSuffix_ScanTest()
        {
            //using var assertionScope = new AssertionScope();

            var cask = new CommonAnnotatedSecurityKey();
            var examples = cask.GenerateTruePositiveExamples().ToList();

            var masker = new IdentifiableScan(WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels,
                                              generateCorrelatingIds: false);

            foreach (string example in examples)
            {
                var exampleWithPrefixOrSuffix = "https://" + example;

                int found = masker.DetectSecrets(exampleWithPrefixOrSuffix).Count();
                found.Should().Be(1);

                exampleWithPrefixOrSuffix = example + "@azuredevops.com";

                found = masker.DetectSecrets(exampleWithPrefixOrSuffix).Count();
                found.Should().Be(1);

                exampleWithPrefixOrSuffix = "https://" + example + "@azuredevops.com";

                found = masker.DetectSecrets(exampleWithPrefixOrSuffix).Count();
                found.Should().Be(1);
            }
        }

        [TestMethod]
        public void GenCode()
        {
            //foreach (var pattern in WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys.OrderBy(p => p.GetType().Name))
            //{
            //    if (pattern is not IFastScannableKey fs)
            //    {
            //        continue;
            //    }
            //    Console.WriteLine($"/*lang=regex*/public const string {pattern.GetType().Name} = @\"\"\"{pattern.Pattern}\"\"\";");
            //}

            foreach (var pattern in WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys.OrderBy(p => p.Id))
            {
                if (pattern is not IFastScannableKey fs)
                {
                    continue;
                }
                foreach (var sig in pattern.Signatures)
                {
                    Console.WriteLine($"new(\"{pattern.Id}\", \"{sig}\", {fs.CharsToScanBeforeSignature}, {fs.CharsToScanBeforeSignature + sig.Length + fs.CharsToScanAfterSignature}, CompiledRegex.{pattern.GetType().Name}()),");
                }
            }
        }

        [TestMethod]
        public void IdentifiableScan_IdentifiableKeys()
        {
            int iterations = 1000;

            using var assertionScope = new AssertionScope();

            var masker = new IdentifiableScan(WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels,
                                              generateCorrelatingIds: false);

            foreach (var pattern in WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys)
            {
                var identifiable = pattern as IIdentifiableKey;
                if (identifiable == null) { continue; }



                foreach (ulong seed in identifiable.ChecksumSeeds)
                {
                    for (int i = 0; i < iterations; i++)
                    {
                        foreach (string signature in identifiable.Signatures)
                        {

                            /* Rust allows base64 where chars where true-positive examples of some patterns do not, nor do their managed regexes :(
                            string key = IdentifiableSecrets.GenerateBase64KeyHelper(seed,
                                                                                     identifiable.KeyLength,
                                                                                     signature,
                                                                                     identifiable.EncodeForUrl);
                            */
                            string key = pattern.GenerateTruePositiveExamples().First();

                            string moniker = pattern.GetMatchMoniker(key);
                            moniker.Should().NotBeNull(because: $"{pattern.Name} should produce a moniker using '{key}'");
                            try
                            {
                                int found = masker.DetectSecrets(key).Count();
                                found.Should().Be(1, because: $"{moniker} should match against '{key}' a single time, not {found} time(s)");
                            }
                            catch
                            {
                                masker.DetectSecrets(key);
                                throw;
                            }
                        }
                    }
                }
            }
        }
    }
}
