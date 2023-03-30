public class SimpleClazz1 {
    private int field1;
    private Integer field2;
    private String field3;
    private int[] field4;

    public SimpleClazz1(String param1) {
        field3 = param1;
    }

    private String method1() {
        return "Whatever";
    }

    public void method2(String param1) {}

    protected String method3(String param1, Integer param2) throws IllegalArgumentException {
        return "Whatever";
    }
}