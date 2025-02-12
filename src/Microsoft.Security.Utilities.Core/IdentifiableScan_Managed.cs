// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Security.Utilities;

/// <summary>
/// A class that can scan data for identifiable secrets.
/// </summary>
public sealed class IdentifiableScan_Managed : ISecretMasker, IDisposable
{
    private bool generateCorrelatingIds;
    private readonly Dictionary<string, IList<RegexPattern>> signatureToPatternsMap;
    private readonly Dictionary<string, ISet<string>> idToSignaturesMap;
    private SecretMasker backupSecretMasker;
    private IRegexEngine regexEngine;
    private List<string> orderedIds;
    private IntPtr scan;

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
        this.regexEngine = regexEngine ?? CachedDotNetRegex.Instance;
        this.generateCorrelatingIds = generateCorrelatingIds;
        this.orderedIds = new List<string>();

        foreach (RegexPattern pattern in regexPatterns)
        {
            if (pattern.Signatures == null || pattern.Signatures.Count == 0)
            {
                throw new NotSupportedException("Not interested in low performance fallback for this experiment.");
                //PopulateBackupMasker(generateCorrelatingIds);
                //
                //this.backupSecretMasker.AddRegex(pattern);
                //continue;
            }

            foreach (string signature in pattern.Signatures)
            {
                if (!HighPerformanceEnabledSignatures.Contains(signature))
                {
                    throw new NotSupportedException("Not interested in low performance fallback for this experiment.");
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
            yield break;
        }

        //// key: signature, value: list of ranges in 
        var signatureFinds = new Dictionary<string, Range>(StringComparer.Ordinal);
        

        //foreach ()


        //// Get indexes and lengths of all substrings that will be replaced.
        //foreach (RegexPattern regexSecret in pa)
        //{
        //    foreach (var detection in regexSecret.GetDetections(input, m_generateCorrelatingIds, DefaultRegexRedactionToken, _regexEngine))
        //    {
        //        yield return detection;
        //    }
        //}

         
    }


    public string MaskSecrets(string input)
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
    }


}
