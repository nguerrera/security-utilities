// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Drawing;

namespace Microsoft.Security.Utilities;

/// <summary>
/// A class that can scan data for identifiable secrets.
/// </summary>
public sealed class IdentifiableScan_Managed : ISecretMasker, IDisposable
{
    private bool generateCorrelatingIds;
    private readonly Dictionary<string, IList<RegexPattern>> signatureToPatternsMap;
    private readonly Dictionary<string, ISet<string>> idToSignaturesMap;

    private static readonly ISet<string> HighPerformanceEnabledSignatures = new HashSet<string>(new string[]
        {
            "+ASt",
            "AzCa",
            "7Q~",
            "8Q~",
            "AzFu",
            "ACDb",
            "+ABa",
            "AzSe",
            "AzSe",
            "+AMC",
            "+ASb",
            "+AEh",
            "+ARm",
            "+ACR",
            "AIoT",
            "APIM",
            "AZEG",
            "JQQJ9",
        });

    public IdentifiableScan_Managed(IEnumerable<RegexPattern> regexPatterns, bool generateCorrelatingIds, IRegexEngine regexEngine = null)
    {
        this.signatureToPatternsMap = new Dictionary<string, IList<RegexPattern>>();
        this.idToSignaturesMap = new Dictionary<string, ISet<string>>();
        this.generateCorrelatingIds = generateCorrelatingIds;

        foreach (RegexPattern pattern in regexPatterns)
        {
            if (pattern.Signatures == null || pattern.Signatures.Count == 0)
            {
                //throw new NotSupportedException("Not interested in low performance fallback for this experiment.");
                //PopulateBackupMasker(generateCorrelatingIds);
                //
                //this.backupSecretMasker.AddRegex(pattern);
                continue;
            }

            foreach (string signature in pattern.Signatures)
            {
                if (!HighPerformanceEnabledSignatures.Contains(signature))
                {
                    //throw new NotSupportedException("Not interested in low performance fallback for this experiment.");
                    //PopulateBackupMasker(generateCorrelatingIds);
                }

                if (!this.idToSignaturesMap.TryGetValue(pattern.Id, out ISet<string> signatures))
                {
                    signatures = new HashSet<string>();
                    this.idToSignaturesMap[pattern.Id] = signatures;
                }
                signatures.Add(signature);

                if (!this.signatureToPatternsMap.TryGetValue(signature, out IList<RegexPattern> patterns))
                {
                    patterns = new List<RegexPattern>();
                    this.signatureToPatternsMap[signature] = patterns;
                }

                patterns.Add(pattern);
            }
        }
    }

    public IEnumerable<Detection> DetectSecrets(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return [];
        }

        var detections = new List<Detection>();

        foreach (var pair in this.signatureToPatternsMap)
        {
            var (signature, patterns) = (pair.Key, pair.Value); 

            // Find all signatures using IndexOf.
            int index = 0;
            var signatureOffsets = new List<int>();
            do
            {
                index = input.IndexOf(signature, index, StringComparison.Ordinal);
                if (index < 0)
                {
                    break;
                }
                signatureOffsets.Add(index);
                index += signature.Length;
            } while (index < input.Length);

            // 
            foreach (var pattern in patterns)
            {
                var regex = CachedDotNetRegex.GetOrCreateRegex(pattern.PatternId, pattern.Pattern, pattern.RegexOptions);
                foreach (var signatureOffset in signatureOffsets)
                {
                    var identifablePattern = (IFastScannableKey)pattern;
                    var start = Math.Max(0, signatureOffset - identifablePattern.CharsToScanBeforeSignature);
                    var end = Math.Min(input.Length, signatureOffset + signature.Length + identifablePattern.CharsToScanAfterSignature);
                    var length = end - start;

                    var rawMatch = regex.Match(input, start, length);
                    if (!rawMatch.Success)
                    {
                        continue;
                    }

                    var match = CachedDotNetRegex.ToFlex(rawMatch, captureGroup: "refine");
                    var found = match.Value;
                    var result = pattern.GetMatchIdAndName(match.Value);

                    if (result != null)
                    {
                        string c3id = null;
                        string preciseId = result.Item1;

                        if (generateCorrelatingIds)
                        {
                            c3id = RegexPattern.GenerateCrossCompanyCorrelatingId(found);
                        }

                        string redactionToken = c3id != null
                            ? $"{preciseId}:{c3id}"
                            : RegexPattern.FallbackRedactionToken;

                        detections.Add(
                            new Detection
                            {
                                Id = preciseId,
                                Name = result.Item2,
                                Start = start + match.Index,
                                Length = found.Length,
                                Metadata = DetectionMetadata.HighEntropy,
                                CrossCompanyCorrelatingId = c3id,
                                RedactionToken = redactionToken,
                            });
                    }
                }
            }
        }
        return detections;
    }


    public string MaskSecrets(string input)
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
    }


}
