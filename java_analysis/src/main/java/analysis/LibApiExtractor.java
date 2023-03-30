package analysis;

import com.google.common.collect.ImmutableList;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.model.SootMethod;
import sootup.core.model.SourceType;
import sootup.java.bytecode.inputlocation.PathBasedAnalysisInputLocation;
import sootup.java.core.JavaProject;
import sootup.java.core.JavaSootClass;
import sootup.java.core.language.JavaLanguage;
import sootup.java.core.views.JavaView;
import sootup.java.sourcecode.inputlocation.JavaSourcePathAnalysisInputLocation;

import java.nio.file.Path;
import java.nio.file.Paths;

public class LibApiExtractor {
    private final JavaLanguage language = new JavaLanguage(8);

    public ImmutableList<ApiInfo> extractAPI(String libPath, boolean isSource) {
        Path path = Paths.get(libPath);
        AnalysisInputLocation<JavaSootClass> location;
        if (isSource) {
            location = new JavaSourcePathAnalysisInputLocation(path.toString());
        } else {
            location = new PathBasedAnalysisInputLocation(path, SourceType.Library);
        }
        JavaProject project = JavaProject.builder(language).addInputLocation(location).build();

        JavaView view = project.createFullView();
        return ImmutableList.copyOf(view.getClasses().stream().flatMap(clazz -> extractApiFromClazz(clazz).stream()).toList());

    }

    private ImmutableList<ApiInfo> extractApiFromClazz(JavaSootClass clazz) {
        ImmutableList.Builder<ApiInfo> builder = ImmutableList.builder();
        for (SootMethod method: clazz.getMethods()) {
            builder.add(ApiInfo.buildApiInfo(method));
        }
        return builder.build();
    }
}
