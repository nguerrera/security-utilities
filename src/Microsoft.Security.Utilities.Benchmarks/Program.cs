
using BenchmarkDotNet.Running;

using Microsoft.Security.Utilities.Benchmarks;

//new RegexEngineDetectionBenchmarks().UseIdentifiableScan();
//new RegexEngineDetectionBenchmarks().UseCachedDotNet();
//new RegexEngineDetectionBenchmarks().UseRE2();

//new HighConfidencePatternsBenchmarks().UseIdentifiableScan_LowLevelCSharp();
var summary = BenchmarkRunner.Run<HighConfidencePatternsBenchmarks>();