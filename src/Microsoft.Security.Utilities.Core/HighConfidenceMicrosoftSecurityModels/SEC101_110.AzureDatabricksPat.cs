﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureDatabricksPat : RegexPattern
    {
        public AzureDatabricksPat()
        {
            Id = "SEC101/110";
            Name = nameof(AzureDatabricksPat);
            DetectionMetadata = DetectionMetadata.HighEntropy;
            Pattern = $"(?:^|[^0-9a-f\\-])(?P<refine>dapi[0-9a-f\\-]{{32,34}})(?:[^0-9a-f\\-]|$)";
        }

        public override IEnumerable<string> GenerateTestExamples()
        {
            yield return $"dapi{WellKnownRegexPatterns.RandomHexadecimal(32)}";
            yield return $"dapi{WellKnownRegexPatterns.RandomHexadecimal(32)}-3";
        }
    }
}