// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities
{
    /// <summary>
    ///  CachedDotNetRegex is an IRegex implementation which pre-compiles all Regexes and then
    ///  calls through to .NET's System.Text.RegularExpressions.Regex.
    /// </summary>
    public class CachedDotNetRegex : IRegexEngine
    {
        public static IRegexEngine Instance { get; } = new CachedDotNetRegex();

        internal static TimeSpan DefaultTimeout = TimeSpan.FromMilliseconds(int.MaxValue - 1);

        private CachedDotNetRegex()
        {
        }

        internal static ConcurrentDictionary<(string Pattern, RegexOptions Options), Regex> RegexCache { get; } = new();

        public static Regex GetOrCreateRegex(string pattern, RegexOptions? options = null)
        {
            (string, RegexOptions) key = (pattern, options ?? RegexDefaults.DefaultOptions);
            return RegexCache.GetOrAdd(key, key => new Regex(NormalizeGroupsPattern(key.Pattern), key.Options));
        }

        internal static string NormalizeGroupsPattern(string pattern)
        {
            return pattern.Replace("?P<", "?<");
        }

        public IEnumerable<UniversalMatch> Matches(string input, string pattern, RegexOptions? options = null, TimeSpan timeout = default, string captureGroup = null)
        {
            if (timeout == default) { timeout = DefaultTimeout; }
            var w = Stopwatch.StartNew();

            Regex regex = GetOrCreateRegex(pattern, options);
            foreach (Match m in regex.Matches(input))
            {
                yield return ToFlex(m, captureGroup);

                // Instance Regex.Matches has no overload; check timeout between matches
                // (MatchesCollection *is* lazily computed).
                if (w.Elapsed > timeout) { break; }
            }
        }

#if NET
        public IEnumerable<UniversalMatch> Matches(ReadOnlySpan<char> input, string pattern, RegexOptions? options = null, TimeSpan timeout = default, string captureGroup = null)
        {
            if (timeout == default) { timeout = DefaultTimeout; }
            var w = Stopwatch.StartNew();

            List<UniversalMatch> list = null;
            Regex regex = GetOrCreateRegex(pattern, options);

            foreach (ValueMatch m in regex.EnumerateMatches(input))
            {
                AddMatch(ref list, input, captureGroup, regex, m);

                // Instance Regex.Matches has no overload; check timeout between matches
                // (MatchesCollection *is* lazily computed).
                if (w.Elapsed > timeout) { break; }
            }

            return (IEnumerable<UniversalMatch>)list ?? Array.Empty<UniversalMatch>();
        }

        private static void AddMatch(ref List<UniversalMatch> list, ReadOnlySpan<char> input, string captureGroup, Regex regex, ValueMatch valueMatch)
        {
            UniversalMatch universalMatch;
            if (captureGroup == null)
            {
                universalMatch = new UniversalMatch
                {
                    Success = true,
                    Index = valueMatch.Index,
                    Length = valueMatch.Length,
                    Value = input.Slice(valueMatch.Index, valueMatch.Length).ToString()
                };
            }
            else
            {
                // https://github.com/dotnet/runtime/issues/73223: There is no
                // capture group support when matching against a span. So we
                // rerun the match against a string that is just the match to
                // get the captures.
                Match rematch = regex.Match(input.Slice(valueMatch.Index, valueMatch.Length).ToString());
                Debug.Assert(rematch.Success, "Expected rematch to succeed.");
                universalMatch = ToFlex(rematch, captureGroup);
                universalMatch.Index += valueMatch.Index; // Adjust index to match original input span
            }

            list ??= new();
            list.Add(universalMatch);
        }
#endif

        internal static UniversalMatch ToFlex(Match match, string captureGroup = null)
        {
            int index = match.Index;
            int length = match.Length;
            string value = match.Value;

            if (captureGroup != null)
            {
                Group group = match.Groups[captureGroup];
                if (group.Success)
                {
                    value = group.Value;
                    index = group.Index;
                    length = group.Length;
                }
            }

            return new UniversalMatch() { Success = match.Success, Index = index, Length = length, Value = value };
        }
    }
}
