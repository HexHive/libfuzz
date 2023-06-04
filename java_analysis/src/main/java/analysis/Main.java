package analysis;

import java.io.*;
import java.util.Map;
import java.util.Set;

public class Main {
    private static final String jarDir = "/jars/";
    private static final String apiFile = "/apis.json";
    private static final String subtypeFile = "/subtypes.json";

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("jarDir and jarFile are not specified");
            return;
        }

        String libDir = args[0];
        String jarFile = args[1];

        try {
            LibAnalyzer analyzer = new LibAnalyzer(libDir + jarDir, jarFile);
            writeApiInfo(analyzer, libDir);
            writeSubTypes(analyzer, libDir);
        } catch (Exception e) {
            e.printStackTrace();
        }

//        Class<?> clazz = FileInputStream.class;
//        LibAnalyzer.extractApiFromClazz(clazz).forEach(System.out::println);
    }


    public static void writeApiInfo(LibAnalyzer analyzer, String dirName) {
        try (FileWriter writer =
                     new FileWriter(dirName + apiFile)) {
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
                     new FileWriter(dirName + subtypeFile)) {
            for (Map.Entry<Arg, Set<Arg>> entry: analyzer.retrieveSubTypes().entrySet()) {
                writer.write(String.format("{\"name\":%s,\"subtypes\":%s}%n", entry.getKey().toString(),
                        entry.getValue().toString()));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
