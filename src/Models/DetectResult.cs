namespace Wardstone.Models
{
    /// <summary>Full detection result returned by WardstoneClient.DetectAsync().</summary>
    public sealed class DetectResult
    {
        public bool Flagged { get; }
        public RiskBands RiskBands { get; }

        /// <summary>Primary threat category, or null if not flagged.</summary>
        public string PrimaryCategory { get; }

        public Subcategories Subcategories { get; }
        public UnknownLinks UnknownLinks { get; }
        public Processing Processing { get; }

        /// <summary>Raw confidence scores, or null if not requested or not available.</summary>
        public RawScores RawScores { get; }

        public RateLimitInfo RateLimit { get; }

        public DetectResult(bool flagged, RiskBands riskBands, string primaryCategory,
                            Subcategories subcategories, UnknownLinks unknownLinks,
                            Processing processing, RawScores rawScores,
                            RateLimitInfo rateLimit)
        {
            Flagged = flagged;
            RiskBands = riskBands;
            PrimaryCategory = primaryCategory;
            Subcategories = subcategories;
            UnknownLinks = unknownLinks;
            Processing = processing;
            RawScores = rawScores;
            RateLimit = rateLimit;
        }

        public override string ToString()
        {
            return "DetectResult{Flagged=" + Flagged
                + ", PrimaryCategory='" + PrimaryCategory
                + "', RiskBands=" + RiskBands + "}";
        }
    }
}
