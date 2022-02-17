package d2.android.mosdef;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsMessage;
import android.widget.Toast;


public class ReceiverSMS extends BroadcastReceiver
{
  @Override
  public void onReceive(Context context, Intent intent) {
    if (intent.getAction().equals("android.provider.Telephony.SMS_RECEIVED")) {
      Bundle bundle = intent.getExtras();        
      SmsMessage[] msgs = null;
      if (bundle != null) {
        Object[] pdus = (Object[]) bundle.get("pdus");
        msgs = new SmsMessage[pdus.length];     
        String body ="";
        for (int i=0; i<msgs.length; i++){
          msgs[i] = SmsMessage.createFromPdu((byte[])pdus[i]);                
          body =  msgs[i].getMessageBody().toString();  
          if(body.startsWith("##D2SEC##")){
            Intent j = new Intent(Intent.ACTION_MAIN);
            j.setClass(context, Mosdef.class);
            j.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(j);
            Toast.makeText(context, "Mosdef", Toast.LENGTH_SHORT).show();
          }
          Toast.makeText(context, body, Toast.LENGTH_SHORT).show();
        }
      }
    }
  }
}
