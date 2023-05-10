import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class Driver0 {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    byte[] byte_d1_0 = data.consumeBytes(10);
    com.fasterxml.jackson.core.JsonFactory jsonfactory_0 = new com.fasterxml.jackson.core.JsonFactory();
    var jsonfactory_1 = jsonfactory_0.copy();
    try {
      var jsonparser_0 = jsonfactory_1.createParser(byte_d1_0);
    } catch (java.io.IOException, com.fasterxml.jackson.core.JsonParseException) {
      return;
    }
    try {
      var string_0 = jsonparser_0.getValueAsString();
    } catch (java.io.IOException) {
      return;
    }
    try {
      var jsontoken_0 = jsonparser_0.nextToken();
    } catch (java.io.IOException) {
      return;
    }
  }
}