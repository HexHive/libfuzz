package analysis;

import com.google.common.collect.ImmutableList;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

public class Arg {
    // This class now only support normal class and simple generic type (e.g. List<String>)
    // If a type is a normal class, rawType is set to the class name and argType is set to empty
    // If a type is a simple generic type, rawType is set to owner (e.g. List) and argType is set to its arguments (e.g. String)
    // Otherwise an exception is thrown
    private String rawType;
    private ImmutableList<String> argType;
    public static Arg buildArg(Type type) throws UnsupportedOperationException {
        if (type instanceof Class) {
            Arg arg = new Arg();
            arg.rawType = ((Class<?>) type).getName();
            arg.argType = ImmutableList.of();
            return arg;
        } else if (type instanceof ParameterizedType) {
            Arg arg = new Arg();
            ImmutableList.Builder<String> builder = ImmutableList.builder();
            for (Type argType: ((ParameterizedType) type).getActualTypeArguments()) {
                if (argType instanceof Class) {
                    builder.add("\"" + ((Class<?>) argType).getName() + "\"");
                } else {
                    throw new UnsupportedOperationException("");
                }
            }
            arg.argType = builder.build();
            Type rawType = ((ParameterizedType) type).getRawType();
            assert rawType instanceof Class;
            arg.rawType = ((Class<?>) rawType).getName();
            return arg;
        }
        throw new UnsupportedOperationException("Unsupported type");
    }

    @Override
    public String toString() {
        return String.format("{\"rawType\":\"%s\",\"argTypes\":%s}", rawType, argType.toString());
    }
}
