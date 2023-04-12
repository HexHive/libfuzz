package analysis;

public class Main {
    public static void main(String[] args) {
        LibAnalyzer analyzer = new LibAnalyzer("C:\\EPFL\\thesis\\libfuzz\\regression_tests\\java_analysis\\test\\lib" +
                "\\SimpleLibrary" +
//                "\\args4j-2.33" +
                ".jar");
        try {
            analyzer.extractAPIs().forEach(System.out::println);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
