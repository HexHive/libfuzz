package analysis;

import com.google.common.collect.ImmutableList;

import java.lang.reflect.*;
import java.util.Arrays;
import java.util.Optional;

public class ApiInfo {
    private String functionName;
    private Arg returnType;
    private ImmutableList<Arg> params;
    private ImmutableList<Arg> exceptions;
    private Arg declaringClazz;
    private int modifier;

    private ApiInfo() {}

    public static Optional<ApiInfo> buildApiInfo(Method method) {
        try {
            ApiInfo info = new ApiInfo();
            info.functionName = method.getName();
            info.params =
                    Arrays.stream(method.getGenericParameterTypes()).map(Arg::buildArg).collect(ImmutableList.toImmutableList());
            info.exceptions = Arrays.stream(method.getGenericExceptionTypes()).map(Arg::buildArg).collect(ImmutableList.toImmutableList());
            info.returnType = Arg.buildArg(method.getGenericReturnType());
            info.modifier = method.getModifiers();
            return Optional.of(info);
        } catch (UnsupportedOperationException e) {
            return Optional.empty();
        }
    }

    public static Optional<ApiInfo> buildApiInfo(Constructor<?> constructor) {
        try {
            ApiInfo info = new ApiInfo();
            info.functionName = constructor.getName();
            info.params =
                    Arrays.stream(constructor.getGenericParameterTypes()).map(Arg::buildArg).collect(ImmutableList.toImmutableList());
            info.exceptions =
                    Arrays.stream(constructor.getGenericExceptionTypes()).map(Arg::buildArg).collect(ImmutableList.toImmutableList());
            info.returnType = Arg.buildArg(constructor.getDeclaringClass());
            info.modifier = constructor.getModifiers();
            return Optional.of(info);
        } catch (UnsupportedOperationException e) {
            return Optional.empty();
        }
    }

    public void setDeclaringClazz(Class<?> klazz) {
        declaringClazz = Arg.buildArg(klazz);
    }

    @Override
    public String toString() {
        String result = "{";

        result += String.format("\"functionName\":\"%s\",", functionName);
        result += String.format("\"returnType\":%s,", returnType);

        result += String.format("\"params\":%s,", params.toString());

        result += String.format("\"exceptions\":%s,", exceptions.toString());

        result += String.format("\"declaringClazz\":%s,", declaringClazz);
        result += String.format("\"modifier\":%d", modifier);

        return result + "}";
    }
}
