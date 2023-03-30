package analysis;

import com.google.common.collect.ImmutableList;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Main {
    public static void main(String[] args) {
        LibApiExtractor extractor = new LibApiExtractor();
        ImmutableList<ApiInfo> apiList = extractor.extractAPI("C:\\EPFL\\thesis\\libfuzz\\regression_tests" +
                        "\\java_analysis" +
                        "\\SimpleLibrary.jar",
                false);
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        for (ApiInfo info: apiList) {
            System.out.println(gson.toJson(info));
        }
    }
}
