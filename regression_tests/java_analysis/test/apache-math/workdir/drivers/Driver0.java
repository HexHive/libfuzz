import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class Driver0 {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    double[] double_d1_0 = new double[data.consumeInt(1, 100)];
    for (int i = 0; i < double_d1_0.length; ++i) {
      double_d1_0[i] = data.consumeDouble();
    }
    org.apache.commons.math3.ml.distance.CanberraDistance canberradistance_0 = new org.apache.commons.math3.ml.distance.CanberraDistance();
    try {
      var double_0 = canberradistance_0.compute(double_d1_0, double_d1_0);
    } catch (org.apache.commons.math3.exception.DimensionMismatchException) {
      return;
    }
  }
}