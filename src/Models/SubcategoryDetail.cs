using System.Collections.Generic;

namespace Wardstone.Models
{
    /// <summary>Subcategory detail containing a list of triggered subtypes.</summary>
    public sealed class SubcategoryDetail
    {
        /// <summary>List of triggered subcategory names.</summary>
        public IReadOnlyList<string> Triggered { get; }

        public SubcategoryDetail(IReadOnlyList<string> triggered)
        {
            Triggered = triggered;
        }

        public override string ToString()
        {
            return "SubcategoryDetail{Triggered=[" + string.Join(", ", Triggered) + "]}";
        }
    }
}
