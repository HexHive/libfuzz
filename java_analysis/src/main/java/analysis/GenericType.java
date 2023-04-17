package analysis;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import java.lang.reflect.Type;
import java.util.*;

public class GenericType {
    private final String typeName;
    public static final Integer nonExistIdx = -1;
    private ImmutableMap<String, ImmutableList<String>> alias;
    private ImmutableMap<String, ImmutableList<Integer>> typeIndex;

    public GenericType(String typeName) {
        this.typeName = typeName;
    }

    public Map<String, ImmutableList<String>> fulfillAlias(Type[] types) {
        Map<String, ImmutableList<String>> result = new HashMap<>();

        for (String typeString: alias.keySet()) {
            List<String> typeList = new ArrayList<>(alias.get(typeString));
            List<Integer> idxList = typeIndex.get(typeString);

            for (int i = 0; i < types.length; i++) {
                Integer idx = idxList.get(i);
                if (!idx.equals(nonExistIdx)) {
                    Type type = types[i];
                    typeList.set(idx, type.getTypeName());
                }
            }

            result.put(typeString, ImmutableList.copyOf(typeList));
        }

        result.put(typeName, Arrays.stream(types).map(Type::getTypeName).collect(ImmutableList.toImmutableList()));

        return result;
    }

    public Map<String, ImmutableList<Integer>> fulfillTypeIndex(List<Integer> indexes) {
        Map<String, ImmutableList<Integer>> result = new HashMap<>();

        for (String typeString: typeIndex.keySet()) {
            List<Integer> typeIdx = typeIndex.get(typeString);
            List<Integer> idxList = new ArrayList<>(indexes);

            for (int i = 0; i < indexes.size(); i++) {
                Integer idx = indexes.get(i);
                if (!idx.equals(nonExistIdx)) {
                    idxList.set(i, typeIdx.get(idx));
                }
            }
            result.put(typeString, ImmutableList.copyOf(idxList));
        }

        result.put(typeName, ImmutableList.copyOf(indexes));

        return result;
    }

    public void setAlias(Map<String, ImmutableList<String>> alias) {
        this.alias = ImmutableMap.copyOf(alias);
    }

    public void setTypeIndex(Map<String, ImmutableList<Integer>> typeIndex) {
        this.typeIndex = ImmutableMap.copyOf(typeIndex);
    }

    public List<Arg> aliasToArgs() {
        return alias.entrySet().stream().map(entry -> new Arg(entry.getKey(), entry.getValue())).toList();
    }
}
