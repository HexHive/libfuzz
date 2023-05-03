import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class Driver0 {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    byte[] byte_d1_0 = data.consumeBytes(10);
    java.io.ByteArrayInputStream bytearrayinputstream_0 = new java.io.ByteArrayInputStream(byte_d1_0);
    co.nstant.in.cbor.CborDecoder cbordecoder_0 = new co.nstant.in.cbor.CborDecoder(bytearrayinputstream_0);
    cbordecoder_0.decode();
  }
}