package analysis;

import java.util.Map;
import java.util.Set;

public class Main {
    public static void main(String[] args) {
        LibAnalyzer analyzer = new LibAnalyzer("C:\\EPFL\\thesis\\libfuzz\\regression_tests\\java_analysis\\test\\lib" +
//                "\\SimpleLibrary" +
                "\\args4j-2.33" +
                ".jar");
        try {
            analyzer.extractAPIs().forEach(System.out::println);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        for (Map.Entry<Arg, Set<Arg>> entry: analyzer.retrieveSubTypes().entrySet()) {
            System.out.printf("{\"name\":%s,\"subtypes\":%s}%n", entry.getKey().toString(),
                    entry.getValue().toString());
        }
    }
}
