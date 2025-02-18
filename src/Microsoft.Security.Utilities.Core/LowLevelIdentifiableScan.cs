// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities;

// A whole lot of complexity is added because there's no way to match a regex against a span on .NET Framework. :(
#if NET
using System.Buffers;
using StringOrSpan = System.ReadOnlySpan<char>;
#else
using StringOrSpan = string;
#endif

internal readonly record struct LowLevelDetection
{
    public string Signature { get; }
    public int Start { get; }
    public int Length { get; }

    public LowLevelDetection(string signature, int start, int length)
    {
        Signature = signature;
        Start = start;
        Length = length;
    }
}

internal sealed partial class LowLevelPattern
{
    /// <summary>
    /// The signature of the pattern. For example, "+ASt" for Azure Storage
    /// Account.
    /// </summary>
    public string Signature { get; }

    /// <summary>
    /// The maximum number of characters that can appear before the signature in
    /// this pattern.
    /// </summary>
    public int MaxLength { get; }

    /// <summary>
    /// The maximum number of characters that can appear before the signature in
    /// this pattern.
    /// </summary>
    public int MaxPreSignatureCharacters { get; }

    /// <summary>
    /// The regular expression that matches the pattern near a signature.
    /// <summary>
    /// <remarks>
    /// WARNING: This is distinct from the general regexes for this pattern that
    /// can be applied to find all matches in a string. This one only needs to
    /// work on input from <see cref="MaxPreSignatureCharacters" /> before
    /// signature to <see cref="MaxLength" /> from there." Furthermore, the
    /// whole expression must correspond to the secret. "refine" capture group
    /// is not used.
    ///
    /// These distinctions are necessary to allow for efficient scanning.
    /// </remarks>
    public Regex Regex { get; }

    private LowLevelPattern(string signature, int maxPreSignatureCharacters, int maxLength, Regex regex)
    {
        Signature = signature;
        MaxPreSignatureCharacters = maxPreSignatureCharacters;
        MaxLength = maxLength;
        Regex = regex;
    }

    // TODO: Generate.
    public static LowLevelPattern AzureStorageAccount { get; } = new("+ASt", 76, 88, LowLevelCompiledRegex.AzureStorageAccount());
    public static LowLevelPattern AadClientLegacy { get; } = new("7Q~", 3, 37, LowLevelCompiledRegex.AadClientLegacy());
    public static LowLevelPattern AadClient { get; } = new("8Q~", 3, 40, LowLevelCompiledRegex.AadClient());
    public static LowLevelPattern AzureCacheForRedis { get; } = new("AzCa", 33, 44, LowLevelCompiledRegex.AzureCacheForRedis());
    public static LowLevelPattern AzureFunction { get; } = new("AzFu", 44, 56, LowLevelCompiledRegex.AzureFunction());
    public static LowLevelPattern AzureCosmosDB { get; } = new("ACDb", 76, 88, LowLevelCompiledRegex.AzureCosmosDB());
    public static LowLevelPattern AzureBatch { get; } = new("+ABa", 76, 88, LowLevelCompiledRegex.AzureBatch());
    public static LowLevelPattern AzureSearch { get; } = new("AzSe", 42, 52, LowLevelCompiledRegex.AzureSearch());
    public static LowLevelPattern AzureMLWebServiceClassic { get; } = new("+AMC", 76, 88, LowLevelCompiledRegex.AzureMLWebServiceClassic());
    public static LowLevelPattern AzureServiceBus { get; } = new("+ASb", 33, 44, LowLevelCompiledRegex.AzureServiceBus());
    public static LowLevelPattern AzureEventHub { get; } = new("+AEh", 33, 44, LowLevelCompiledRegex.AzureEventHub());
    public static LowLevelPattern AzureRelay { get; } = new("+ARm", 33, 44, LowLevelCompiledRegex.AzureRelay());
    public static LowLevelPattern AzureContainerRegistry { get; } = new("+ACR", 42, 52, LowLevelCompiledRegex.AzureContainerRegistry());
    public static LowLevelPattern AzureIot { get; } = new("AIoT", 33, 44, LowLevelCompiledRegex.AzureIot());
    public static LowLevelPattern AzureApim { get; } = new("APIM", 76, 88, LowLevelCompiledRegex.AzureApim());
    public static LowLevelPattern HISv2 { get; } = new("JQQJ9", 52, 88, LowLevelCompiledRegex.HISv2());

    public static ImmutableArray<LowLevelPattern> All { get; } = [
        AzureStorageAccount,
        AadClientLegacy,
        AadClient,
        AzureCacheForRedis,
        AzureFunction,
        AzureCosmosDB,
        AzureBatch,
        AzureSearch,
        AzureMLWebServiceClassic,
        AzureServiceBus,
        AzureEventHub,
        AzureRelay,
        AzureContainerRegistry,
        AzureIot,
        AzureApim,
        HISv2,
    ];
}

internal static partial class LowLevelSecretScanner
{
    public static IReadOnlyList<LowLevelDetection> Scan(StringOrSpan input, IEnumerable<LowLevelPattern> patterns = null)
    {
#if !NET
        if (input == null)
        {
            throw new ArgumentNullException(nameof(input));
        }
#endif
        if (input.Length == 0)
        {
            return [];
        }

        var detections = new List<LowLevelDetection>();
        int index = 0;
        do
        {
            var pattern = FindNextSignature(input, ref index);
            if (pattern == null)
            {
                break;
            }

            int start = Math.Max(0, index - pattern.MaxPreSignatureCharacters);
            int end = Math.Min(input.Length, index + pattern.MaxLength);
            int length = (end - start);

            if (Match(pattern.Regex, input, ref start, ref length, ref index))
            {
                detections.Add(new(pattern.Signature, start, length));
            }
            else
            {
                index += pattern.Signature.Length;
            }

        } while (index < input.Length);

        return detections;
    }

    private static bool Match(Regex regex, StringOrSpan input, ref int start, ref int length, ref int index)
    {
#if NET
        Regex.ValueMatchEnumerator matches = regex.EnumerateMatches(input.Slice(start, length));
        if (!matches.MoveNext())
        {
            return false;
        }
        ValueMatch match = matches.Current;
#else
        Match match = regex.Match(input, start, length);
        if (!match.Success)
        {
            return false;
        }
#endif
        start += match.Index;
        index = (start + match.Length);
        length = match.Length;
        return true;
    }

    private static LowLevelPattern FindNextSignature(StringOrSpan input, ref int index)
    {
#if NET9_0_OR_GREATER
        int offset = input.Slice(index).IndexOfAny(s_signatures);
        if (offset < 0)
        {
            return null;
        }
        index += offset;
        return GetPatternForKnownSignature(input.Slice(index));
#else
        while (true)
        {
#if NET
            int offset = input.Slice(index).IndexOfAny(s_signatureStarts);
            if (offset < 0)
            {
                return null;
            }
            index += offset;
#else
            index = input.IndexOfAny(s_signatureStarts, index);
#endif 
            if (index < 0)
            {
                return null;
            }

            var pattern = GetPatternForPossibleSignature(input, index);
            if (pattern == null)
            {
                index++;
                continue;
            }

            return pattern;
       }
#endif
    }

#if NET9_0_OR_GREATER
    private static readonly SearchValues<string> s_signatures = SearchValues.Create([
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
        "JQQJ"
     ], StringComparison.Ordinal);
#elif NET
    private static readonly SearchValues<char> s_signatureStarts = SearchValues.Create([ '+','7', '8','A','J']);
#else
    private static readonly char[] s_signatureStarts = ['+', '7', '8', 'A', 'J'];
#endif

#if NET9_0_OR_GREATER
    private static LowLevelPattern GetPatternForKnownSignature(ReadOnlySpan<char> signature)
    {
        switch (signature[0])
        {
            case '+':
                switch (signature[2])
                {
                    case 'B': return LowLevelPattern.AzureBatch;
                    case 'C': return LowLevelPattern.AzureContainerRegistry;
                    case 'E': return LowLevelPattern.AzureEventHub;
                    case 'M': return LowLevelPattern.AzureMLWebServiceClassic;
                    case 'R': return LowLevelPattern.AzureRelay;
                    case 'S':
                        switch (signature[3])
                        {
                            case 't': return LowLevelPattern.AzureStorageAccount;
                            case 'b': return LowLevelPattern.AzureServiceBus;
                        }
                        break;
                }
                break;
            case '7': return LowLevelPattern.AadClientLegacy;
            case '8': return LowLevelPattern.AadClient;
            case 'A':
                switch (signature[1])
                {
                    case 'C': return LowLevelPattern.AzureCosmosDB;
                    case 'I': return LowLevelPattern.AzureIot;
                    case 'P': return LowLevelPattern.AzureApim;
                    case 'z':
                        switch (signature[2])
                        {
                            case 'C': return LowLevelPattern.AzureCacheForRedis;
                            case 'F': return LowLevelPattern.AzureFunction;
                            case 'S': return LowLevelPattern.AzureSearch;
                        }
                        break;
                }
                break;
            case 'J': return LowLevelPattern.HISv2;
        }

        throw new InvalidOperationException("BUG: This code path should not be reachable.");
    }
#else
    private static LowLevelPattern GetPatternForPossibleSignature(StringOrSpan input, int index)
    {
#if NET
        var signature = input.Slice(index);
#else
        var signature = input.AsSpan(index);
#endif
        switch (signature[0])
        {
            case '+':
                switch (signature[1])
                {
                    case 'A':
                        switch (signature[2])
                        {
                            case 'S':
                                switch (signature[3])
                                {
                                    case 't': return LowLevelPattern.AzureStorageAccount;
                                    case 'b': return LowLevelPattern.AzureServiceBus;
                                }
                                break;
                            case 'B':
                                if (signature[3] == 'a')
                                {
                                    return LowLevelPattern.AzureBatch;
                                }
                                break;
                            case 'M':
                                if (signature[3] == 'C')
                                {
                                    return LowLevelPattern.AzureMLWebServiceClassic;
                                }
                                break;
                            case 'E':
                                if (signature[3] == 'h')
                                {
                                    return LowLevelPattern.AzureEventHub;
                                }
                                break;
                            case 'R':
                                if (signature[3] == 'm')
                                {
                                    return LowLevelPattern.AzureRelay;
                                }
                                break;
                            case 'C':
                                if (signature[3] == 'R')
                                {
                                    return LowLevelPattern.AzureContainerRegistry;
                                }
                                break;
                        }
                        break;
                }
                break;
            case 'A':
                switch (signature[1])
                {
                    case 'z':
                        switch (signature[2])
                        {
                            case 'C':
                                if (signature[3] == 'a')
                                {
                                    return LowLevelPattern.AzureCacheForRedis;
                                }
                                break;
                            case 'F':
                                if (signature[3] == 'u')
                                {
                                    return LowLevelPattern.AzureFunction;
                                }
                                break;
                            case 'S':
                                if (signature[3] == 'e')
                                {
                                    return LowLevelPattern.AzureSearch;
                                }
                                break;
                        }
                        break;
                    case 'I':
                        if (signature[2] == 'o' && signature[3] == 'T')
                        {
                            return LowLevelPattern.AzureIot;
                        }
                        break;
                    case 'P':
                        if (signature[2] == 'I' && signature[3] == 'M')
                        {
                            return LowLevelPattern.AzureApim;
                        }
                        break;
                    case 'C':
                        if (signature[2] == 'D' && signature[3] == 'b')
                        {
                            return LowLevelPattern.AzureCosmosDB;
                        }
                        break;
                }
                break;
            case '7':
                if (signature[1] == 'Q' && signature[2] == '~')
                {
                    return LowLevelPattern.AadClientLegacy;
                }
                break;
            case '8':
                if (signature[1] == 'Q' && signature[2] == '~')
                {
                    return LowLevelPattern.AadClient;
                }
                break;
            case 'J':
                if (signature[1] == 'Q' && signature[2] == 'Q' && signature[3] == 'J')
                {
                    return LowLevelPattern.HISv2;
                }
                break;
        }
        return null;
    }
#endif
}

/*lang=regex*/
internal static class LowLevelLiteralRegex
{
    public const string AadClientLegacy = """^[~.a-zA-Z0-9_\-]{3}7Q~[~.a-zA-Z0-9_\-]{31}""";
    public const string AadClient = """^[~.a-zA-Z0-9_\-]{3}8Q~[~.a-zA-Z0-9_\-]{34}""";
    public const string AzureApim = """^[a-zA-Z0-9+/]{76}APIM[a-zA-Z0-9+/]{5}[AQgw]==""";
    public const string AzureBatch = """^[a-zA-Z0-9+/]{76}\+ABa[a-zA-Z0-9+/]{5}[AQgw]==""";
    public const string AzureCacheForRedis = """^[a-zA-Z0-9+/]{33}AzCa[A-P][a-zA-Z0-9+/]{5}=""";
    public const string AzureContainerRegistry = """^[a-zA-Z0-9+/]{42}\+ACR[A-D][a-zA-Z0-9+/]{5}""";
    public const string AzureCosmosDB = """^[a-zA-Z0-9+/]{76}ACDb[a-zA-Z0-9+/]{5}[AQgw]==""";
    public const string AzureEventGrid = """^[a-zA-Z0-9+/]{33}AZEG[A-P][a-zA-Z0-9+/]{5}=""";
    public const string AzureEventHub = """^[a-zA-Z0-9+/]{33}\+AEh[A-P][a-zA-Z0-9+/]{5}=""";
    public const string AzureFunction = """^[a-zA-Z0-9_\-]{44}AzFu[a-zA-Z0-9_\-]{5}[AQgw]==""";
    public const string AzureIot = """^[a-zA-Z0-9+/]{33}AIoT[A-P][a-zA-Z0-9+/]{5}=""";
    public const string AzureMLWebServiceClassic = """^[a-zA-Z0-9+/]{76}\+AMC[a-zA-Z0-9+/]{5}[AQgw]==""";
    public const string AzureRelay = """^[a-zA-Z0-9+/]{33}\+ARm[A-P][a-zA-Z0-9+/]{5}=""";
    public const string AzureSearch = """^[a-zA-Z0-9]{42}AzSe[A-D][a-zA-Z0-9]{5}""";
    public const string AzureServiceBus = """^[a-zA-Z0-9+/]{33}\+ASb[A-P][a-zA-Z0-9+/]{5}=""";
    public const string AzureStorageAccount = """^[a-zA-Z0-9+/]{76}\+ASt[a-zA-Z0-9+/]{5}[AQgw]==""";
    public const string HISv2 = """^[a-zA-Z0-9]{52}JQQJ9(9|D|H)[a-zA-Z0-9][A-L][a-zA-Z0-9]{16}[A-Za-z][a-zA-Z0-9]{7}(?:[a-zA-Z0-9]{2}==)?""";
}

internal static partial class LowLevelCompiledRegex
{
    public const RegexOptions Options = RegexOptions.ExplicitCapture | RegexOptions.Compiled | RegexOptions.CultureInvariant;

#if NET
    [GeneratedRegex(LowLevelLiteralRegex.AadClientLegacy, Options)] public static partial Regex AadClientLegacy();
    [GeneratedRegex(LowLevelLiteralRegex.AadClient, Options)] public static partial Regex AadClient();
    [GeneratedRegex(LowLevelLiteralRegex.AzureApim, Options)] public static partial Regex AzureApim();
    [GeneratedRegex(LowLevelLiteralRegex.AzureBatch, Options)] public static partial Regex AzureBatch();
    [GeneratedRegex(LowLevelLiteralRegex.AzureCacheForRedis, Options)] public static partial Regex AzureCacheForRedis();
    [GeneratedRegex(LowLevelLiteralRegex.AzureContainerRegistry, Options)] public static partial Regex AzureContainerRegistry();
    [GeneratedRegex(LowLevelLiteralRegex.AzureCosmosDB, Options)] public static partial Regex AzureCosmosDB();
    [GeneratedRegex(LowLevelLiteralRegex.AzureEventGrid, Options)] public static partial Regex AzureEventGrid();
    [GeneratedRegex(LowLevelLiteralRegex.AzureEventHub, Options)] public static partial Regex AzureEventHub();
    [GeneratedRegex(LowLevelLiteralRegex.AzureFunction, Options)] public static partial Regex AzureFunction();
    [GeneratedRegex(LowLevelLiteralRegex.AzureIot, Options)] public static partial Regex AzureIot();
    [GeneratedRegex(LowLevelLiteralRegex.AzureMLWebServiceClassic, Options)] public static partial Regex AzureMLWebServiceClassic();
    [GeneratedRegex(LowLevelLiteralRegex.AzureRelay, Options)] public static partial Regex AzureRelay();
    [GeneratedRegex(LowLevelLiteralRegex.AzureSearch, Options)] public static partial Regex AzureSearch();
    [GeneratedRegex(LowLevelLiteralRegex.AzureServiceBus, Options)] public static partial Regex AzureServiceBus();
    [GeneratedRegex(LowLevelLiteralRegex.AzureStorageAccount, Options)] public static partial Regex AzureStorageAccount();
    [GeneratedRegex(LowLevelLiteralRegex.HISv2, Options)] public static partial Regex HISv2();
#else
    public static Regex AadClientLegacy() => new(LowLevelLiteralRegex.AadClientLegacy, Options);
    public static Regex AadClient() => new(LowLevelLiteralRegex.AadClient, Options);
    public static Regex AzureApim() => new(LowLevelLiteralRegex.AzureApim, Options);
    public static Regex AzureBatch() => new(LowLevelLiteralRegex.AzureBatch, Options);
    public static Regex AzureCacheForRedis() => new(LowLevelLiteralRegex.AzureCacheForRedis, Options);
    public static Regex AzureContainerRegistry() => new(LowLevelLiteralRegex.AzureContainerRegistry, Options);
    public static Regex AzureCosmosDB() => new(LowLevelLiteralRegex.AzureCosmosDB, Options);
    public static Regex AzureEventGrid() => new(LowLevelLiteralRegex.AzureEventGrid, Options);
    public static Regex AzureEventHub() => new(LowLevelLiteralRegex.AzureEventHub, Options);
    public static Regex AzureFunction() => new(LowLevelLiteralRegex.AzureFunction, Options);
    public static Regex AzureIot() => new(LowLevelLiteralRegex.AzureIot, Options);
    public static Regex AzureMLWebServiceClassic() => new(LowLevelLiteralRegex.AzureMLWebServiceClassic, Options);
    public static Regex AzureRelay() => new(LowLevelLiteralRegex.AzureRelay, Options);
    public static Regex AzureSearch() => new(LowLevelLiteralRegex.AzureSearch, Options);
    public static Regex AzureServiceBus() => new(LowLevelLiteralRegex.AzureServiceBus, Options);
    public static Regex AzureStorageAccount() => new(LowLevelLiteralRegex.AzureStorageAccount, Options);
    public static Regex HISv2() => new(LowLevelLiteralRegex.HISv2, Options);
#endif
}


