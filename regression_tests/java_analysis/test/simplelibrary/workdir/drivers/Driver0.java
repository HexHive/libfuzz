import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class Driver0 {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    SimpleClazz3 simpleclazz3_0 = new SimpleClazz3();
    int int_0 = data.consumeInt();
    SimpleClazz4 simpleclazz4_0 = new SimpleClazz4();
    var int_1 = simpleclazz4_0.method2(int_0);
    SimpleClazz2 simpleclazz2_0 = new SimpleClazz2();
    var string_0 = simpleclazz2_0.method4(simpleclazz3_0, int_1);
  }
}