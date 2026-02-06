using System.Collections.Generic;

namespace Wardstone.Models
{
    /// <summary>Unknown links detection data.</summary>
    public sealed class UnknownLinks
    {
        public bool Flagged { get; }
        public int UnknownCount { get; }
        public int KnownCount { get; }
        public int TotalUrls { get; }
        public IReadOnlyList<string> UnknownDomains { get; }

        public UnknownLinks(bool flagged, int unknownCount, int knownCount,
                            int totalUrls, IReadOnlyList<string> unknownDomains)
        {
            Flagged = flagged;
            UnknownCount = unknownCount;
            KnownCount = knownCount;
            TotalUrls = totalUrls;
            UnknownDomains = unknownDomains;
        }

        public override string ToString()
        {
            return "UnknownLinks{Flagged=" + Flagged
                + ", UnknownCount=" + UnknownCount
                + ", KnownCount=" + KnownCount
                + ", TotalUrls=" + TotalUrls + "}";
        }
    }
}
