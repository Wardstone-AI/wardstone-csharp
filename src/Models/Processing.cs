namespace Wardstone.Models
{
    /// <summary>Processing metadata from the API response.</summary>
    public sealed class Processing
    {
        public double InferenceMs { get; }
        public int InputLength { get; }
        public string ScanStrategy { get; }
        public int? ChunksScanned { get; }
        public int? TotalChunks { get; }

        public Processing(double inferenceMs, int inputLength, string scanStrategy,
                          int? chunksScanned, int? totalChunks)
        {
            InferenceMs = inferenceMs;
            InputLength = inputLength;
            ScanStrategy = scanStrategy;
            ChunksScanned = chunksScanned;
            TotalChunks = totalChunks;
        }

        public override string ToString()
        {
            return "Processing{InferenceMs=" + InferenceMs
                + ", InputLength=" + InputLength
                + ", ScanStrategy='" + ScanStrategy + "'}";
        }
    }
}
