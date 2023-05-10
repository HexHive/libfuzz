package analysis;

import java.io.*;
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
//                    "\\args4j-2.33" +
//                    "\\cbor-0.9" +
//                    "\\zxing-3.5.1" +
//                    "\\spring-boot-3.0.6" +
                    "\\hamcrest-2.2" +
                    ".jar");

            String dirName = "hamcrest";
            writeApiInfo(analyzer, dirName);
            writeSubTypes(analyzer, dirName);
        } catch (Exception e) {
            e.printStackTrace();
        }

//        Class<?> clazz = FileInputStream.class;
//        LibAnalyzer.extractApiFromClazz(clazz).forEach(System.out::println);
    }


    public static void writeApiInfo(LibAnalyzer analyzer, String dirName) {
        try (FileWriter writer =
                     new FileWriter("C:\\EPFL\\thesis\\libfuzz\\regression_tests\\java_analysis\\test\\" + dirName +
                             "\\apis.json")) {
            analyzer.extractAPIs().forEach(apiinfo -> {
                try {
                    writer.write(apiinfo.toString() + "\n");
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void writeSubTypes(LibAnalyzer analyzer, String dirName) {
        try (FileWriter writer =
                     new FileWriter("C:\\EPFL\\thesis\\libfuzz\\regression_tests\\java_analysis\\test\\" + dirName +
                             "\\subtypes.json")) {
            for (Map.Entry<Arg, Set<Arg>> entry: analyzer.retrieveSubTypes().entrySet()) {
                writer.write(String.format("{\"name\":%s,\"subtypes\":%s}%n", entry.getKey().toString(),
                        entry.getValue().toString()));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
