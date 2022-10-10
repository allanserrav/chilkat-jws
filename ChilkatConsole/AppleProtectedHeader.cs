using Newtonsoft.Json;
using System.Collections.Generic;

namespace ChilkatConsole
{
    public class AppleProtectedHeader
    {
        [JsonProperty("alg")]
        public string Alg { get; set; }
        [JsonProperty("x5c")]
        public IEnumerable<string> X5C { get; set; }
    }
}
