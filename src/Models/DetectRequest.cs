namespace Wardstone.Models
{
    /// <summary>Request builder for the detect endpoint.</summary>
    public sealed class DetectRequest
    {
        /// <summary>The text to analyze.</summary>
        public string Text { get; }

        /// <summary>Scan strategy: "early-exit", "full-scan", or "smart-sample".</summary>
        public string ScanStrategy { get; set; }

        /// <summary>Whether to include raw confidence scores in the response.</summary>
        public bool? IncludeRawScores { get; set; }

        public DetectRequest(string text)
        {
            Text = text;
        }
    }
}
