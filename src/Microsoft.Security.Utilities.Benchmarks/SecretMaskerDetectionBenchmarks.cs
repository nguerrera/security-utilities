// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Security.Utilities.Benchmarks
{
    public abstract class SecretMaskerDetectionBenchmarks
    {
        // The size of randomized data to add as a prefix
        // for every secret. This is intended to make positive
        // hit less concentrated in the profiling.
        private const int SecretPrefixSize = 100 * 1000;
        private const int SecretPostfixSize = 1000;

        private static readonly char[] chars = GenerateRandomData(SecretPrefixSize + SecretPostfixSize);
        private static readonly byte[] bytes = Encoding.UTF8.GetBytes(chars);

        private static char[] GenerateRandomData(int size)
        {
            var random = new Random();
            var data = new byte[size];
            random.NextBytes(data);
            return Convert.ToBase64String(data).ToCharArray();
        }

        // Whether to generate correlating ids for each match.
        // Setting this to true will contribute fixed hash
        // production overhead to all the scanners.
        protected virtual bool GenerateCorrelatingIds => false;

        protected abstract IEnumerable<RegexPattern> RegexPatterns { get; }

        [Benchmark]
        public void UseIdentifiableScan_LowLevelCSharp()
        {
            int count = 0;
            foreach (var pattern in RegexPatterns)
            {
                foreach (string example in pattern.GenerateTruePositiveExamples())
                {
                    chars.AsSpan()[SecretPrefixSize..].Clear();
                    example.CopyTo(chars.AsSpan()[SecretPrefixSize..]);
                    var detections = LowLevelIdentifiableScan.Scan(chars.AsSpan().Slice(0, SecretPrefixSize + example.Length));
                    if (detections.Count != 1)
                    {
                        throw new InvalidOperationException($"Regex {pattern.Name} failed to detect example {example}");
                    }
                    count++;
                }
            }

            if (count != 849)
            {
                throw new InvalidOperationException("Wrong number of matches");
            }
        }

        [Benchmark]
        public void UseIdentifiableScan_Rust()
        {
            int count = 0;
            IntPtr scan = identifiable_scan_create(null, 0);
            foreach (var pattern in RegexPatterns)
            {
                foreach (string example in pattern.GenerateTruePositiveExamples())
                {
                    // slight penalty for rust here for UTF8 conversion
                    bytes.AsSpan()[SecretPrefixSize..].Clear();
                    Encoding.UTF8.GetBytes(example, bytes.AsSpan()[SecretPrefixSize..]);

                    var detections = identifiable_scan_oneshot_for_bench(scan, bytes, SecretPrefixSize + example.Length);
                    if (detections != 1)
                    {
                        throw new InvalidOperationException($"Regex {pattern.Name} failed to detect example {example}");
                    }
                    count++;
                }
            }

            if (count != 849)
            {
                throw new InvalidOperationException("Wrong number of matches");
            }
        }

        [DllImport("microsoft_security_utilities_core")]
        static extern IntPtr identifiable_scan_create(
            byte[]? filter,
            nuint size);


        [DllImport("microsoft_security_utilities_core")]
        static extern int identifiable_scan_oneshot_for_bench(
            IntPtr scan,
            byte[] bytes,
            int length);
    }
}
