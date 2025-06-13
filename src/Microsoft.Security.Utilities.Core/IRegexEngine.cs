// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Diagnostics;

namespace Microsoft.Security.Utilities
{
    public interface IRegexEngine
    {
        IEnumerable<UniversalMatch> Matches(string input, string pattern, RegexOptions? options = null, TimeSpan timeout = default, string captureGroup = null);

#if NET
        public IEnumerable<UniversalMatch> Matches(ReadOnlyMemory<char> input, string pattern, RegexOptions? options = null, TimeSpan timeout = default, string captureGroup = null)
        {
            throw new NotSupportedException("Regex engine does not support memory input.");
        }
#endif
    }

    internal static class RegexEngineExtensions
    {
        internal static IEnumerable<UniversalMatch> Matches(this IRegexEngine engine, StringInput input, string pattern, RegexOptions? options = null, TimeSpan timeout = default, string captureGroup = null)
        {
#if NET
            if (input.TryGetString(out string s))
            {
                return engine.Matches(s, pattern, options, timeout, captureGroup);
            }
            else
            {
                return engine.Matches(input.Memory, pattern, options, timeout, captureGroup);
            }
#else
            return engine.Matches(input.String, pattern, options, timeout, captureGroup);
#endif
        }
    }
}
