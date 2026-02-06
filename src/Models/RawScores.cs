using System.Collections.Generic;

namespace Wardstone.Models
{
    /// <summary>Optional raw confidence scores (paid plans only).</summary>
    public sealed class RawScores
    {
        public IReadOnlyDictionary<string, double> Categories { get; }
        public IReadOnlyDictionary<string, double> ContentViolationSubs { get; }
        public IReadOnlyDictionary<string, double> DataLeakageSubs { get; }

        public RawScores(IReadOnlyDictionary<string, double> categories,
                         IReadOnlyDictionary<string, double> contentViolationSubs,
                         IReadOnlyDictionary<string, double> dataLeakageSubs)
        {
            Categories = categories;
            ContentViolationSubs = contentViolationSubs;
            DataLeakageSubs = dataLeakageSubs;
        }

        public override string ToString()
        {
            return "RawScores{Categories=" + Categories.Count + " entries}";
        }
    }
}
