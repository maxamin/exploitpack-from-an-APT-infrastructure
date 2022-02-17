package d2.android.mosdef;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class ReceiverSecretCode extends BroadcastReceiver
{
  @Override
  public void onReceive(Context context, Intent intent) {
    if (intent.getAction().equals("android.provider.Telephony.SECRET_CODE")) {
      Intent i = new Intent(Intent.ACTION_MAIN);
      i.setClass(context, Mosdef.class);
      i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
      context.startActivity(i);
    }
  }
}
