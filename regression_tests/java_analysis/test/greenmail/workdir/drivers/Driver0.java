import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class Driver0 {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    com.icegreen.greenmail.util.GreenMail greenmail_0 = new com.icegreen.greenmail.util.GreenMail();
    String string_0 = data.consumeString(100);
    String string_1 = data.consumeString(100);
    var usermanager_0 = greenmail_0.getUserManager();
    try {
      var greenmailuser_0 = usermanager_0.createUser(string_0, string_0, string_1);
    } catch (com.icegreen.greenmail.user.UserException e ) {
      return;
    }
  }
}