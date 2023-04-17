package analysis;

import org.checkerframework.checker.units.qual.A;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Main {
    public static void main(String[] args) {
        try {
            LibAnalyzer analyzer = new LibAnalyzer("C:\\EPFL\\thesis\\libfuzz\\regression_tests\\java_analysis\\test" +
                    "\\lib" +
//                    "\\SimpleLibrary" +
                    "\\args4j-2.33" +
                    ".jar");
            analyzer.extractAPIs().forEach(System.out::println);
//            for (Map.Entry<Arg, Set<Arg>> entry: analyzer.retrieveSubTypes().entrySet()) {
//                System.out.printf("{\"name\":%s,\"subtypes\":%s}%n", entry.getKey().toString(),
//                        entry.getValue().toString());
//            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

}
