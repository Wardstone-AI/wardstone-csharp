using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Wardstone.Internal
{
    /// <summary>
    /// Minimal JSON parser/serializer for the limited shapes needed by the SDK.
    /// Keeps the SDK zero-dependency (no Newtonsoft/System.Text.Json required).
    /// </summary>
    internal sealed class Json
    {
        private const int MaxNestingDepth = 128;
        private const int MaxNumberLength = 30;
        private const int MaxStringLength = 1_048_576; // 1 MB per string value
        private const int MaxContainerEntries = 10_000;
        private const int MaxInputLength = 10 * 1024 * 1024; // 10 MB, matches MaxResponseBytes

        private readonly string _input;
        private int _pos;
        private int _depth;

        private Json(string input)
        {
            _input = input;
            _pos = 0;
            _depth = 0;
        }

        /// <summary>Parse a JSON string into a Dictionary, List, string, double, bool, or null.</summary>
        public static object Parse(string json)
        {
            if (string.IsNullOrEmpty(json))
            {
                throw new ArgumentException("Empty JSON input");
            }
            // Strip UTF-8 BOM if present (some HTTP responses include it)
            if (json[0] == '\uFEFF')
            {
                json = json.Substring(1);
                if (json.Length == 0)
                {
                    throw new ArgumentException("Empty JSON input");
                }
            }
            if (json.Length > MaxInputLength)
            {
                throw new ArgumentException("JSON input too large (" + json.Length + " characters, max " + MaxInputLength + ")");
            }
            var parser = new Json(json);
            object result = parser.ParseValue();
            parser.SkipWhitespace();
            if (parser._pos < parser._input.Length)
            {
                throw parser.Error("Unexpected trailing content at position " + parser._pos);
            }
            return result;
        }

        /// <summary>Serialize a Dictionary/List/string/number/bool/null to a JSON string.</summary>
        public static string Stringify(object value)
        {
            return StringifyValue(value, 0);
        }

        private static string StringifyValue(object value, int depth)
        {
            if (depth > MaxNestingDepth)
            {
                throw new ArgumentException("Maximum nesting depth exceeded (" + MaxNestingDepth + ") during serialization");
            }
            if (value == null)
            {
                return "null";
            }
            if (value is string s)
            {
                return StringifyString(s);
            }
            if (value is bool b)
            {
                return b ? "true" : "false";
            }
            if (value is double d)
            {
                if (double.IsNaN(d) || double.IsInfinity(d))
                {
                    throw new ArgumentException("Cannot serialize non-finite double value: " + d);
                }
                return d.ToString("G", CultureInfo.InvariantCulture);
            }
            if (value is int i)
            {
                return i.ToString(CultureInfo.InvariantCulture);
            }
            if (value is long l)
            {
                return l.ToString(CultureInfo.InvariantCulture);
            }
            if (value is IDictionary<string, object> dict)
            {
                return StringifyMap(dict, depth);
            }
            if (value is IList<object> list)
            {
                return StringifyList(list, depth);
            }
            return StringifyString(value.ToString());
        }

        private static string StringifyString(string s)
        {
            var sb = new StringBuilder(s.Length + 2);
            sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                        {
                            sb.AppendFormat("\\u{0:x4}", (int)c);
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        private static string StringifyMap(IDictionary<string, object> map, int depth)
        {
            var sb = new StringBuilder();
            sb.Append('{');
            bool first = true;
            foreach (var entry in map)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append(StringifyString(entry.Key));
                sb.Append(':');
                sb.Append(StringifyValue(entry.Value, depth + 1));
            }
            sb.Append('}');
            return sb.ToString();
        }

        private static string StringifyList(IList<object> list, int depth)
        {
            var sb = new StringBuilder();
            sb.Append('[');
            bool first = true;
            foreach (object item in list)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append(StringifyValue(item, depth + 1));
            }
            sb.Append(']');
            return sb.ToString();
        }

        // --- Parser ---

        private object ParseValue()
        {
            SkipWhitespace();
            if (_pos >= _input.Length)
            {
                throw Error("Unexpected end of input");
            }
            char c = _input[_pos];
            switch (c)
            {
                case '{':
                case '[':
                    if (++_depth > MaxNestingDepth)
                    {
                        throw Error("Maximum nesting depth exceeded (" + MaxNestingDepth + ")");
                    }
                    try
                    {
                        return c == '{' ? (object)ParseObject() : ParseArray();
                    }
                    finally
                    {
                        _depth--;
                    }
                case '"': return ParseString();
                case 't':
                case 'f': return ParseBoolean();
                case 'n': return ParseNull();
                default:
                    if (c == '-' || (c >= '0' && c <= '9'))
                    {
                        return ParseNumber();
                    }
                    throw Error("Unexpected character: '" + c + "'");
            }
        }

        private Dictionary<string, object> ParseObject()
        {
            Expect('{');
            var map = new Dictionary<string, object>();
            SkipWhitespace();
            if (_pos < _input.Length && _input[_pos] == '}')
            {
                _pos++;
                return map;
            }
            while (true)
            {
                if (map.Count >= MaxContainerEntries)
                {
                    throw Error("Object has too many keys (max " + MaxContainerEntries + ")");
                }
                SkipWhitespace();
                string key = ParseString();
                SkipWhitespace();
                Expect(':');
                object value = ParseValue();
                map[key] = value;
                SkipWhitespace();
                if (_pos >= _input.Length)
                {
                    throw Error("Unexpected end of object");
                }
                if (_input[_pos] == '}')
                {
                    _pos++;
                    return map;
                }
                Expect(',');
            }
        }

        private List<object> ParseArray()
        {
            Expect('[');
            var list = new List<object>();
            SkipWhitespace();
            if (_pos < _input.Length && _input[_pos] == ']')
            {
                _pos++;
                return list;
            }
            while (true)
            {
                if (list.Count >= MaxContainerEntries)
                {
                    throw Error("Array has too many elements (max " + MaxContainerEntries + ")");
                }
                list.Add(ParseValue());
                SkipWhitespace();
                if (_pos >= _input.Length)
                {
                    throw Error("Unexpected end of array");
                }
                if (_input[_pos] == ']')
                {
                    _pos++;
                    return list;
                }
                Expect(',');
            }
        }

        private string ParseString()
        {
            Expect('"');
            // Pre-allocate with reasonable initial capacity to reduce reallocation
            int remaining = _input.Length - _pos;
            int initialCap = Math.Min(remaining, 1024);
            var sb = new StringBuilder(initialCap);
            while (_pos < _input.Length)
            {
                if (sb.Length >= MaxStringLength)
                {
                    throw Error("String value too long (max " + MaxStringLength + " characters)");
                }
                char c = _input[_pos++];
                if (c == '"')
                {
                    return sb.ToString();
                }
                if (c == '\\')
                {
                    if (_pos >= _input.Length)
                    {
                        throw Error("Unexpected end of string escape");
                    }
                    char esc = _input[_pos++];
                    switch (esc)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            if (_pos + 4 > _input.Length)
                            {
                                throw Error("Incomplete unicode escape");
                            }
                            string hex = _input.Substring(_pos, 4);
                            _pos += 4;
                            int codePoint;
                            if (!int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out codePoint))
                            {
                                throw Error("Invalid unicode escape: \\u" + hex);
                            }
                            // Surrogate pair validation
                            if (codePoint >= 0xD800 && codePoint <= 0xDBFF)
                            {
                                // High surrogate: must be followed by \uDC00-\uDFFF
                                if (_pos + 6 > _input.Length || _input[_pos] != '\\' || _input[_pos + 1] != 'u')
                                {
                                    throw Error("High surrogate \\u" + hex + " must be followed by a low surrogate (\\uDC00-\\uDFFF)");
                                }
                                string lowHex = _input.Substring(_pos + 2, 4);
                                int lowCode;
                                if (!int.TryParse(lowHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out lowCode)
                                    || lowCode < 0xDC00 || lowCode > 0xDFFF)
                                {
                                    throw Error("High surrogate \\u" + hex + " must be followed by a low surrogate (\\uDC00-\\uDFFF), got \\u" + lowHex);
                                }
                                _pos += 6; // skip \uXXXX
                                sb.Append((char)codePoint);
                                sb.Append((char)lowCode);
                            }
                            else if (codePoint >= 0xDC00 && codePoint <= 0xDFFF)
                            {
                                // Lone low surrogate
                                throw Error("Lone low surrogate \\u" + hex + " without preceding high surrogate");
                            }
                            else
                            {
                                sb.Append((char)codePoint);
                            }
                            break;
                        default:
                            throw Error("Unknown escape: \\" + esc);
                    }
                }
                else if (c < 0x20)
                {
                    // RFC 8259: unescaped control characters (U+0000 through U+001F) are not allowed in JSON strings
                    throw Error("Unescaped control character U+" + ((int)c).ToString("X4") + " in string");
                }
                else
                {
                    sb.Append(c);
                }
            }
            throw Error("Unterminated string");
        }

        private object ParseNumber()
        {
            int start = _pos;
            if (_pos < _input.Length && _input[_pos] == '-') _pos++;
            if (_pos >= _input.Length) throw Error("Unexpected end of number");

            if (_input[_pos] == '0')
            {
                _pos++;
                // Reject leading zeros (e.g., 01, 007) per JSON spec
                if (_pos < _input.Length && _input[_pos] >= '0' && _input[_pos] <= '9')
                {
                    throw Error("Leading zeros are not allowed in JSON numbers");
                }
            }
            else if (_input[_pos] >= '1' && _input[_pos] <= '9')
            {
                while (_pos < _input.Length && _input[_pos] >= '0' && _input[_pos] <= '9')
                {
                    if (_pos - start > MaxNumberLength) throw Error("Number literal too long");
                    _pos++;
                }
            }
            else
            {
                throw Error("Invalid number");
            }

            bool isFloat = false;
            if (_pos < _input.Length && _input[_pos] == '.')
            {
                isFloat = true;
                _pos++;
                if (_pos >= _input.Length || _input[_pos] < '0' || _input[_pos] > '9')
                {
                    throw Error("Invalid number: decimal point must be followed by digits");
                }
                while (_pos < _input.Length && _input[_pos] >= '0' && _input[_pos] <= '9')
                {
                    if (_pos - start > MaxNumberLength) throw Error("Number literal too long");
                    _pos++;
                }
            }
            if (_pos < _input.Length && (_input[_pos] == 'e' || _input[_pos] == 'E'))
            {
                isFloat = true;
                _pos++;
                if (_pos < _input.Length && (_input[_pos] == '+' || _input[_pos] == '-')) _pos++;
                if (_pos >= _input.Length || _input[_pos] < '0' || _input[_pos] > '9')
                {
                    throw Error("Invalid number: exponent must contain digits");
                }
                while (_pos < _input.Length && _input[_pos] >= '0' && _input[_pos] <= '9')
                {
                    if (_pos - start > MaxNumberLength) throw Error("Number literal too long");
                    _pos++;
                }
            }

            string numStr = _input.Substring(start, _pos - start);
            if (numStr.Length > MaxNumberLength)
            {
                throw Error("Number literal too long");
            }
            if (isFloat)
            {
                double result = double.Parse(numStr, CultureInfo.InvariantCulture);
                if (double.IsInfinity(result) || double.IsNaN(result))
                {
                    throw Error("Number value out of range: " + numStr);
                }
                return result;
            }
            long val;
            if (!long.TryParse(numStr, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out val))
            {
                throw Error("Integer value out of range: " + numStr);
            }
            if (val >= int.MinValue && val <= int.MaxValue)
            {
                return (int)val;
            }
            return val;
        }

        private object ParseBoolean()
        {
            if (_pos + 4 <= _input.Length && _input.Substring(_pos, 4) == "true")
            {
                _pos += 4;
                return true;
            }
            if (_pos + 5 <= _input.Length && _input.Substring(_pos, 5) == "false")
            {
                _pos += 5;
                return false;
            }
            throw Error("Expected 'true' or 'false'");
        }

        private object ParseNull()
        {
            if (_pos + 4 <= _input.Length && _input.Substring(_pos, 4) == "null")
            {
                _pos += 4;
                return null;
            }
            throw Error("Expected 'null'");
        }

        private void SkipWhitespace()
        {
            while (_pos < _input.Length)
            {
                char c = _input[_pos];
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
                _pos++;
            }
        }

        private void Expect(char expected)
        {
            SkipWhitespace();
            if (_pos >= _input.Length || _input[_pos] != expected)
            {
                throw Error("Expected '" + expected + "'");
            }
            _pos++;
        }

        private ArgumentException Error(string msg)
        {
            return new ArgumentException("JSON parse error at position " + _pos + ": " + msg);
        }
    }
}
