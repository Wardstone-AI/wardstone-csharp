namespace Wardstone.Models
{
    /// <summary>Rate limit information parsed from response headers.</summary>
    public sealed class RateLimitInfo
    {
        public int Limit { get; }
        public int Remaining { get; }
        public int Reset { get; }

        public RateLimitInfo(int limit, int remaining, int reset)
        {
            Limit = limit;
            Remaining = remaining;
            Reset = reset;
        }

        public override string ToString()
        {
            return "RateLimitInfo{Limit=" + Limit
                + ", Remaining=" + Remaining
                + ", Reset=" + Reset + "}";
        }
    }
}
