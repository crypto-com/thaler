import java.util.Map;

public class CroBindings {
    native String jsonrpc(String storeage, String url, String request);  
    // load so library    
    static {
      System.loadLibrary("CroBindings"); 
   }
}
