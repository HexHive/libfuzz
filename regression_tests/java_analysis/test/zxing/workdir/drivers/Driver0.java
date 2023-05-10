import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class Driver0 {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    byte[] byte_d1_0 = data.consumeBytes(10);
    int int_0 = data.consumeInt();
    int int_1 = data.consumeInt();
    int int_2 = data.consumeInt();
    com.google.zxing.pdf417.PDF417ResultMetadata pdf417resultmetadata_0 = new com.google.zxing.pdf417.PDF417ResultMetadata();
    var int_d1_0 = pdf417resultmetadata_0.getOptionalData();
    com.google.zxing.RGBLuminanceSource rgbluminancesource_0 = new com.google.zxing.RGBLuminanceSource(int_2, int_0, int_d1_0);
    var luminancesource_0 = rgbluminancesource_0.rotateCounterClockwise();
    com.google.zxing.InvertedLuminanceSource invertedluminancesource_0 = new com.google.zxing.InvertedLuminanceSource(luminancesource_0);
    var luminancesource_1 = invertedluminancesource_0.rotateCounterClockwise45();
    com.google.zxing.common.HybridBinarizer hybridbinarizer_0 = new com.google.zxing.common.HybridBinarizer(luminancesource_0);
    var binarizer_0 = hybridbinarizer_0.createBinarizer(luminancesource_1);
    com.google.zxing.BinaryBitmap binarybitmap_0 = new com.google.zxing.BinaryBitmap(binarizer_0);
    var binarybitmap_1 = binarybitmap_0.rotateCounterClockwise();
    com.google.zxing.oned.UPCEANReader upceanreader_0 = new com.google.zxing.oned.UPCEANReader();
    try {
      var result_0 = upceanreader_0.decode(binarybitmap_1);
    } catch (com.google.zxing.NotFoundException, com.google.zxing.FormatException) {
      return;
    }
    com.google.zxing.client.result.TelResultParser telresultparser_0 = new com.google.zxing.client.result.TelResultParser();
    var telparsedresult_0 = telresultparser_0.parse(result_0);
    var string_0 = telparsedresult_0.getTelURI();
    var decodehinttype_0 = com.google.zxing.DecodeHintType.valueOf(string_0);
    var string_1 = decodehinttype_0.name();
    com.google.zxing.NotFoundException notfoundexception_0 = new com.google.zxing.NotFoundException();
    var string_2 = notfoundexception_0.toString();
    com.google.zxing.client.result.WifiParsedResult wifiparsedresult_0 = new com.google.zxing.client.result.WifiParsedResult(string_1, string_2, string_2);
    var boolean_0 = wifiparsedresult_0.isHidden();
    com.google.zxing.PlanarYUVLuminanceSource planaryuvluminancesource_0 = new com.google.zxing.PlanarYUVLuminanceSource(byte_d1_0, int_1, int_1, int_0, int_1, int_1, int_0, boolean_0);
    var int_3 = planaryuvluminancesource_0.getThumbnailHeight();
    var boolean_1 = invertedluminancesource_0.isCropSupported();
    com.google.zxing.PlanarYUVLuminanceSource planaryuvluminancesource_1 = new com.google.zxing.PlanarYUVLuminanceSource(byte_d1_0, int_0, int_0, int_0, int_0, int_1, int_3, boolean_1);
    var luminancesource_2 = planaryuvluminancesource_1.rotateCounterClockwise45();
    com.google.zxing.InvertedLuminanceSource invertedluminancesource_1 = new com.google.zxing.InvertedLuminanceSource(luminancesource_2);
    var luminancesource_3 = invertedluminancesource_1.invert();
    com.google.zxing.common.HybridBinarizer hybridbinarizer_1 = new com.google.zxing.common.HybridBinarizer(luminancesource_1);
    var binarizer_1 = hybridbinarizer_1.createBinarizer(luminancesource_3);
    com.google.zxing.BinaryBitmap binarybitmap_2 = new com.google.zxing.BinaryBitmap(binarizer_1);
    com.google.zxing.oned.EAN13Reader ean13reader_0 = new com.google.zxing.oned.EAN13Reader();
    try {
      var result_1 = ean13reader_0.decode(binarybitmap_2);
    } catch (com.google.zxing.NotFoundException, com.google.zxing.FormatException) {
      return;
    }
    com.google.zxing.MultiFormatReader multiformatreader_0 = new com.google.zxing.MultiFormatReader();
    var string_3 = result_1.getText();
    try {
      var result_2 = multiformatreader_0.decode(binarybitmap_2);
    } catch (com.google.zxing.NotFoundException) {
      return;
    }
    var map_resultmetadatatype_object_0 = result_1.getResultMetadata();
  }
}