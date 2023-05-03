package analysis;

import com.google.common.collect.ImmutableList;
import sootup.core.types.ClassType;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Arg {
    // This class now only support normal class and simple generic type (e.g. List<String>)
    // If a type is a normal class, rawType is set to the class name and argType is set to empty
    // If a type is a simple generic type, rawType is set to owner (e.g. List) and argType is set to its arguments (e.g. String)
    // Otherwise an exception is thrown
    private static final Set<String> primitive = Set.of("void", "byte", "int", "short", "long", "float", "double",
            "boolean", "char");
    private String rawType;
    private ImmutableList<String> argType;

    public Arg() {}

    public Arg(String rawType, List<String> argTypes) {
        this.rawType = rawType;
        this.argType = ImmutableList.copyOf(argTypes);
    }

    public Arg(Class<?> clazz) {
        this.rawType = clazz.getName();
        this.argType = ImmutableList.of();
    }

    public static Arg buildArg(Type type) throws UnsupportedOperationException {
        Arg arg = new Arg();
        if (type instanceof Class<?> classType) {
            arg.rawType = classType.getName();
            arg.argType = ImmutableList.of();
            return arg;
        } else if (type instanceof ParameterizedType parameterizedType) {
            ImmutableList.Builder<String> builder = ImmutableList.builder();
            for (Type argType: parameterizedType.getActualTypeArguments()) {
                if (argType instanceof Class<?> classType) {
                    builder.add(classType.getName());
                } else {
                    throw new UnsupportedOperationException("");
                }
            }
            arg.argType = builder.build();
            Type rawType = parameterizedType.getRawType();
            assert rawType instanceof Class;
            arg.rawType = ((Class<?>) rawType).getName();
            return arg;
        }
        throw new UnsupportedOperationException("Unsupported type");
    }

    @Override
    public String toString() {
        return String.format("{\"rawType\":\"%s\",\"argTypes\":%s}", formatName(rawType),
                argType.stream().map(type -> "\"" + formatName(type) + "\"").toList());
    }

    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + rawType.hashCode();
        result = 31 * result + argType.hashCode();
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof Arg a)) {
            return false;
        }

        return a.rawType.equals(rawType) && a.argType.equals(argType);
    }

    private static String formatName(String name) {
        String s = name;
        String h = "";
        if (name.startsWith("[")) {
            int idx = name.indexOf("[L");
            if (idx == -1) {
                return name;
            }
            s = name.substring(idx + 2);
            h = name.substring(0, idx + 2);
        }

        if (!primitive.contains(s) && !s.contains(".")) {
            return h + "." + s;
        }
        return h + s;
    }
}
