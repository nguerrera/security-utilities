﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class Integer : RegexPattern
    {
        public Integer()
        {
            Id = "DAT101/003";
            Name = nameof(Integer);
            Pattern = @"^-?\d+$";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return "-0001";
            yield return "0";
            yield return "1";
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            yield return "0.0";

            // Formatted numbers are not supported.
            yield return "1,000";
        }
    }
}
