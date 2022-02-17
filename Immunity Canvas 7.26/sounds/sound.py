#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
sound.py

word... that file is a mess...

"""

import sys, os, subprocess
sys.path.append('.')

from internal import devlog
from engine import CanvasConfig as config

has_winsound = False
if sys.platform == 'win32' and os.name == 'nt':
    try:
        import winsound
        has_winsound = True
    except ImportError:
        pass


SOUNDDIR = "sounds"
SOUNDCFG = SOUNDDIR + os.path.sep + "sound.cfg"
soundvar={}

def configsound():
    if not config['sound']:
        return 0
    
    try:
        os.stat(SOUNDDIR)
    except OSError:
        return 0
    
    try:
        os.stat(SOUNDCFG)
    except OSError:
        return 0
    
    fd = open(SOUNDCFG, "r")
    for a in fd.readlines():
        a=a.strip()
        if not a or a[0]=="#":
            continue
        vars=a.split("=")
        #print vars
        if len(vars) != 2:
            continue
    
        if vars[0]=="OWN":
            if not soundvar.has_key(vars[0]):
                soundvar[vars[0]]=[]
            soundvar[vars[0]].append(vars[1])
        else:
            soundvar[vars[0]]=vars[1]
    fd.close()
        
    # CHECK IF play works is there
    if soundvar.has_key("OWN"):
        import random
        random.shuffle(soundvar["OWN"])
    
    if not has_winsound:
        #play_path=["/usr/bin/play", "/bin/play", "/usr/sbin/play", "/usr/local/bin/play"]
        for player in config['sound_player']:
            try:
                os.stat(player)
            except OSError:
                continue
            return 1
        
        print "No player found at %s. Try adding manually to CANVAS/%s" % (str(play_path), SOUNDCFG)
        return 0
    
    return 1   

def play(VAR):
    """ Attempt to play a sound """
    
    if not config['sound'] or (not has_winsound and not config['sound_player']):
        devlog('sound::play', "No sounds")
        return 0
    
    if not soundvar.has_key(VAR):
        print "var '%s' not configured, check %s" % (VAR, SOUNDCFG)
        return 0
    
    devlog('sound::play', "name = %s" % VAR)
    wav = soundvar[VAR]
    if VAR == "OWN":
        ownndx=-1
        if ownndx == (len(soundvar[VAR])-1):
            ownndx = 0
        else:
            ownndx += 1
        wav = soundvar[VAR][ownndx]
    
    wav = os.getcwd() + os.path.sep + "sounds" + os.path.sep + wav 
    if has_winsound:
        if not wav[-3:].upper() == "WAV":
            devlog('sound::play', "winsound.PlaySound only plays .wav files! can not play %s" % wav)
        else:
            try:
                devlog('sound::play', "WIN32 PlaySound %s" % wav)
                winsound.PlaySound(wav, winsound.SND_FILENAME|winsound.SND_NOWAIT)
            except:
                config['sound'] = False
                pass
    else:
        player = "%s" % (config['sound_player'])
        if config['sound_player_options']:
            player += " %s "%config['sound_player_options']
            
        devlog('sound::play', "UNIX command: %s %s" % (player, wav))
        try:
            subprocess.Popen( [player, wav], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            ##Likely file could not be found
            print "Problem with sound player. Check the config file that the correct player and options are specified."

    return 1

if __name__=="__main__":
    config['sound'] = True
    configsound()
    import time
    play("WELCOME")
    time.sleep(1)
    play("OWN")
