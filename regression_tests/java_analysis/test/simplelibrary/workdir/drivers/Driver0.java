import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class Driver0 {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    SimpleClazz4 simpleclazz4_0 = new SimpleClazz4();
    int int_0 = data.consumeInt();
    SimpleClazz2 simpleclazz2_0 = new SimpleClazz2();
    var string_0 = simpleclazz2_0.method4(simpleclazz4_0, int_0);
  }
}