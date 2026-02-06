namespace Wardstone.Models
{
    /// <summary>Container for subcategory details.</summary>
    public sealed class Subcategories
    {
        public SubcategoryDetail ContentViolation { get; }
        public SubcategoryDetail DataLeakage { get; }

        public Subcategories(SubcategoryDetail contentViolation, SubcategoryDetail dataLeakage)
        {
            ContentViolation = contentViolation;
            DataLeakage = dataLeakage;
        }

        public override string ToString()
        {
            return "Subcategories{ContentViolation=" + ContentViolation
                + ", DataLeakage=" + DataLeakage + "}";
        }
    }
}
