// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#if NET9_0_OR_GREATER
// TODO: IS there a good enough polyfill of IndexOfAny(SV<string>) for .NET 8? .NET fx
// A standalone, optimized version of IdentifiableScan entirely decoupled from Microsoft.Security.Utilities.
// This one will be measured against pure Rust so it shouldn't have any baggage from Microsoft.Security.Utilities.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities;

internal readonly record struct LowLevelDetection(string Id, int Start, int Length);

internal static partial class LowLevelIdentifiableScan
{
    // TODO: provide a way to speciy which patterns to scan for.
    //
    // TODO: Implement streaming.
    // Also. Use a sliding window to catch a secret that spans multiple chunks.
    //       Current implementation in Microsoft.Security.Utilities does not handle that.
    //

    public static IReadOnlyList<LowLevelDetection> Scan(ReadOnlySpan<char> input)
    {
        if (input.IsEmpty)
        {
            return [];
        }

        var detections = new List<LowLevelDetection>();
        var index = 0;
        do
        {
            index = input[index..].IndexOfAny(s_signatureSearch);

            if (index < 0)
            {
                break;
            }

            ref readonly var pattern = ref GetForPatternForSignature(input[index..]);
            var start = Math.Max(0, index - pattern.CharsBeforeSignature);
            var end = Math.Min(input.Length, index + pattern.MaxLength);
            var matchEnumerator = pattern.Regex.EnumerateMatches(input[start..end]);

            if (matchEnumerator.MoveNext())
            {
                var match = matchEnumerator.Current;
                detections.Add(new(pattern.Id, start + match.Index, match.Length));
                index = start + match.Length;
            }
            else
            {
                index = end;
            }
        } while (index < input.Length);

        return detections;
    }

    //*************************************************************************************************************************
    // *** TODO: Generate the code for everything below here from the existing pattern data in Microsoft.Security.Utilities ***
    // ** I wrote some junky throwaway code to generate and hand-edited for now.                                            ***
    //*************************************************************************************************************************
    private readonly record struct Pattern(string Id, string Signature, int CharsBeforeSignature, int MaxLength, Regex Regex)
    {
        public static readonly Pattern AzureStorageAccount = new("SEC101/152", "+ASt", 76, 88, CompiledRegex.AzureStorageAccount());
        public static readonly Pattern AadClientLegacy = new("SEC101/156", "7Q~", 3, 37, CompiledRegex.AadClientLegacy());
        public static readonly Pattern AadClient = new("SEC101/156", "8Q~", 3, 40, CompiledRegex.AadClient());
        public static readonly Pattern AzureCacheForRedis = new("SEC101/154", "AzCa", 33, 44, CompiledRegex.AzureCacheForRedis());
        public static readonly Pattern AzureFunction = new("SEC101/158", "AzFu", 44, 56, CompiledRegex.AzureFunction());
        public static readonly Pattern AzureCosmosDB = new("SEC101/160", "ACDb", 76, 88, CompiledRegex.AzureCosmosDB());
        public static readonly Pattern AzureBatch = new("SEC101/163", "+ABa", 76, 88, CompiledRegex.AzureBatch());
        public static readonly Pattern AzureSearch = new("SEC101/166", "AzSe", 42, 52, CompiledRegex.AzureSearch());
        public static readonly Pattern AzureMLWebServiceClassic = new("SEC101/170", "+AMC", 76, 88, CompiledRegex.AzureMLWebServiceClassic());
        public static readonly Pattern AzureServiceBus = new("SEC101/171", "+ASb", 33, 44, CompiledRegex.AzureServiceBus());
        public static readonly Pattern AzureEventHub = new("SEC101/172", "+AEh", 33, 44, CompiledRegex.AzureEventHub());
        public static readonly Pattern AzureRelay = new("SEC101/173", "+ARm", 33, 44, CompiledRegex.AzureRelay());
        public static readonly Pattern AzureContainerRegistry = new("SEC101/176", "+ACR", 42, 52, CompiledRegex.AzureContainerRegistry());
        public static readonly Pattern AzureIot = new("SEC101/178", "AIoT", 33, 44, CompiledRegex.AzureIot());
        public static readonly Pattern AzureApim = new("SEC101/181", "APIM", 76, 88, CompiledRegex.AzureApim());
        public static readonly Pattern HISv2 = new("SEC101/200", "JQQJ", 52, 88, CompiledRegex.HISv2());
    }

    private static readonly SearchValues<string> s_signatureSearch
        = SearchValues.Create([
            "+ABa",
            "+ACR",
            "+AEh",
            "+AMC",
            "+ARm",
            "+ASb",
            "+ASt",
            "7Q~",
            "8Q~",
            "ACDb",
            "AIoT",
            "APIM",
            "AzCa",
            "AzFu",
            "AzSe",
            "JQQJ",
            ], StringComparison.Ordinal);

    private static ref readonly Pattern GetForPatternForSignature(ReadOnlySpan<char> signature)
    {
        switch (signature[0])
        {
            case '+':
                Debug.Assert(signature[1] == 'A');
                switch (signature[2])
                {
                    case 'B': return ref Pattern.AzureBatch;
                    case 'C': return ref Pattern.AzureContainerRegistry;
                    case 'E': return ref Pattern.AzureEventHub;
                    case 'M': return ref Pattern.AzureMLWebServiceClassic;
                    case 'R': return ref Pattern.AzureRelay;
                    case 'S':
                        switch (signature[3])
                        {
                            case 't': return ref Pattern.AzureStorageAccount;
                            case 'b': return ref Pattern.AzureServiceBus;
                        }
                        break;
                }
                break;
            case '7': return ref Pattern.AadClientLegacy;
            case '8': return ref Pattern.AadClient;
            case 'A':
                switch (signature[1])
                {
                    case 'C': return ref Pattern.AzureCosmosDB;
                    case 'I': return ref Pattern.AzureIot;
                    case 'P': return ref Pattern.AzureApim;
                    case 'z':
                        switch (signature[2])
                        {
                            case 'C': return ref Pattern.AzureCacheForRedis;
                            case 'F': return ref Pattern.AzureFunction;
                            case 'S': return ref Pattern.AzureSearch;
                        }
                        break;
                }
                break;
            case 'J': return ref Pattern.HISv2;
        }

        throw new InvalidOperationException("BUG: This code path should not be reachable.");
    }

    /*lang=regex*/
    private static class LiteralRegex
    {
        public const string AadClientLegacy = """^[~.a-zA-Z0-9_\-]{3}7Q~[~.a-zA-Z0-9_\-]{31}""";
        public const string AadClient = """^[~.a-zA-Z0-9_\-]{3}8Q~[~.a-zA-Z0-9_\-]{34}""";
        public const string AzureApim = """^[a-zA-Z0-9+/]{76}APIM[a-zA-Z0-9+/]{5}[AQgw]==""";
        public const string AzureBatch = """^[a-zA-Z0-9+/]{76}\+ABa[a-zA-Z0-9+/]{5}[AQgw]==""";
        public const string AzureCacheForRedis = """^[a-zA-Z0-9+/]{33}AzCa[A-P][a-zA-Z0-9+/]{5}=""";
        public const string AzureContainerRegistry = """^[a-zA-Z0-9+/]{42}\+ACR[A-D][a-zA-Z0-9+/]{5}""";
        public const string AzureCosmodDB = """^[a-zA-Z0-9+/]{76}ACDb[a-zA-Z0-9+/]{5}[AQgw]==""";
        public const string AzureEventGrid = """^[a-zA-Z0-9+/]{33}AZEG[A-P][a-zA-Z0-9+/]{5}=""";
        public const string AzureEventHub = """^[a-zA-Z0-9+/]{33}\+AEh[A-P][a-zA-Z0-9+/]{5}=""";
        public const string AzureFunction = """^[a-zA-Z0-9_\-]{44}AzFu[a-zA-Z0-9_\-]{5}[AQgw]==""";
        public const string AzureIot = """^[a-zA-Z0-9+/]{33}AIoT[A-P][a-zA-Z0-9+/]{5}=""";
        public const string AzureMLWebServiceClassic = """^[a-zA-Z0-9+/]{76}\+AMC[a-zA-Z0-9+/]{5}[AQgw]==""";
        public const string AzureRelay = """^[a-zA-Z0-9+/]{33}\+ARm[A-P][a-zA-Z0-9+/]{5}=""";
        public const string AzureSearch = """^[a-zA-Z0-9]{42}AzSe[A-D][a-zA-Z0-9]{5}""";
        public const string AzureServiceBug = """^[a-zA-Z0-9+/]{33}\+ASb[A-P][a-zA-Z0-9+/]{5}=""";
        public const string AzureStorageAccount = """^[a-zA-Z0-9+/]{76}\+ASt[a-zA-Z0-9+/]{5}[AQgw]==""";
        public const string HISv2 = """^[a-zA-Z0-9]{52}JQQJ9(9|D|H)[a-zA-Z0-9][A-L][a-zA-Z0-9]{16}[A-Za-z][a-zA-Z0-9]{7}(?:[a-zA-Z0-9]{2}==)?""";
    }

    static partial class CompiledRegex
    {
        private const RegexOptions _options = RegexOptions.ExplicitCapture | RegexOptions.Compiled | RegexOptions.CultureInvariant;
        [GeneratedRegex(LiteralRegex.AadClientLegacy, _options)] public static partial Regex AadClientLegacy();
        [GeneratedRegex(LiteralRegex.AadClient, _options)] public static partial Regex AadClient();
        [GeneratedRegex(LiteralRegex.AzureApim, _options)] public static partial Regex AzureApim();
        [GeneratedRegex(LiteralRegex.AzureBatch, _options)] public static partial Regex AzureBatch();
        [GeneratedRegex(LiteralRegex.AzureCacheForRedis, _options)] public static partial Regex AzureCacheForRedis();
        [GeneratedRegex(LiteralRegex.AzureContainerRegistry, _options)] public static partial Regex AzureContainerRegistry();
        [GeneratedRegex(LiteralRegex.AzureCosmodDB, _options)] public static partial Regex AzureCosmosDB();
        [GeneratedRegex(LiteralRegex.AzureEventGrid, _options)] public static partial Regex AzureEventGrid();
        [GeneratedRegex(LiteralRegex.AzureEventHub, _options)] public static partial Regex AzureEventHub();
        [GeneratedRegex(LiteralRegex.AzureFunction, _options)] public static partial Regex AzureFunction();
        [GeneratedRegex(LiteralRegex.AzureIot, _options)] public static partial Regex AzureIot();
        [GeneratedRegex(LiteralRegex.AzureMLWebServiceClassic, _options)] public static partial Regex AzureMLWebServiceClassic();
        [GeneratedRegex(LiteralRegex.AzureRelay, _options)] public static partial Regex AzureRelay();
        [GeneratedRegex(LiteralRegex.AzureSearch, _options)] public static partial Regex AzureSearch();
        [GeneratedRegex(LiteralRegex.AzureServiceBug, _options)] public static partial Regex AzureServiceBus();
        [GeneratedRegex(LiteralRegex.AzureStorageAccount, _options)] public static partial Regex AzureStorageAccount();
        [GeneratedRegex(LiteralRegex.HISv2, _options)] public static partial Regex HISv2();
    }
}
#endif


