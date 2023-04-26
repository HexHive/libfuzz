public class SimpleClazz2 {
    private int field1;
    private Integer field2;
    private String field3;
    private int[] field4;

    private SimpleClazz2() {
    }

    private String[][] method1() {
        return new String[][] {{"Whatever"}};
    }

    public void method2(String param1) {}

    protected String method3(String param1, Integer param2) throws IllegalArgumentException {
        return "Whatever";
    }

    public String method4(SimpleClazz3 clazz, int param) {
        return "Whatever";
    }
}