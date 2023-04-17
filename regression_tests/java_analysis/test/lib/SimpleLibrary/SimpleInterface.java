import java.util.Map;

public interface SimpleInterface<T> extends SimpleSuperInterface<Integer, T> {
    T method1(int param);
}