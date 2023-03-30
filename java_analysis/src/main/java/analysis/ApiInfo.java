package analysis;

import com.google.common.collect.ImmutableList;
import com.google.gson.Gson;
import sootup.core.model.SootMethod;
import sootup.core.types.ClassType;
import sootup.core.types.Type;

import java.io.FileWriter;
import java.io.IOException;

public class ApiInfo {
    public enum Acess {
        PUBLIC,
        PRIVATE,
        PROTECTED
    }

    private String functionName;
    private Type returnType;
    private ImmutableList<Type> params;
    private ImmutableList<Type> exceptions;
    private ClassType declaringClazz;
    private boolean isStatic;
    private boolean isFinal;
    private boolean isAbstract;
    private Acess accessModifier;

    private ApiInfo() {}

    public static ApiInfo buildApiInfo(SootMethod method) {
        ApiInfo info = new ApiInfo();
        info.isStatic = method.isStatic();
        info.functionName = method.getName();
        info.returnType = method.getReturnType();
        info.params = ImmutableList.copyOf(method.getParameterTypes());
        info.exceptions = ImmutableList.copyOf(method.getExceptionSignatures());
        info.declaringClazz = method.getDeclaringClassType();
        info.isFinal = method.isFinal();
        info.isAbstract = method.isAbstract();

        if (method.isPrivate()) {
            info.accessModifier = Acess.PRIVATE;
        } else if (method.isProtected()) {
            info.accessModifier = Acess.PROTECTED;
        } else if (method.isPublic()) {
            info.accessModifier = Acess.PUBLIC;
        } else {
            // Why this will happen?
        }

        return info;
    }
}
