import java.util.List;
import java.util.Map;

public class SimpleClazz3 implements SimpleInterface<Map<Integer, String>> {
    private List<String> field1;

    public Map<Integer, String> method1(int param) {
        return Map.of(param, "");
    }

    private class InnerClass {
        public static void method0() {}
    }
}