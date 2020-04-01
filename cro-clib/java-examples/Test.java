public class Test {
    static public void main(String argv[]) {        
        CroBindings sdk = new CroBindings();              
         System.out.printf("CRO_NAME=%s\n", System.getenv("CRO_NAME"));
         System.out.printf("CRO_PASSPHRASE=%s\n", System.getenv("CRO_PASSPHRASE"));
         System.out.printf("CRO_ENCKEY=%s\n", System.getenv("CRO_ENCKEY"));
         System.out.printf("CRO_MNEMONICS=%s\n", System.getenv("CRO_MNEMONICS"));
         String storage= ".storage";
         String url= "ws://localhost:26657/websocket";       
         String request="{\"jsonrpc\": \"2.0\", \"method\": \"wallet_list\", \"params\": [], \"id\": 1}";       
         System.out.printf("storage=%s   url=%s  request=%s\n", storage, url, request);   
         String b=sdk.jsonrpc(storage,url, request);
         System.out.printf("java => receive from c %s! \n", b);
      }
}