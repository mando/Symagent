#!/bin/sh

# $Id: thump.sh 55 2008-09-30 19:26:52Z mando $
# AgentSDK
# stop/start the local agent
#
# Mike ERWIN mikee@symbiot.com
# Paco NATHAN paco@symbiot.com
# Jamie PUGH jamie@symbiot.com

nuke ()
{
    ps axl | grep $1 | grep -v grep | perl -e 'while (<STDIN>) { s/\s+/ /g; @l = split(/ /); print $l[2] . "\n"; }' |
    while read pid
    do
      printf "kill pid %6d  %s\n" $pid $1
      sudo kill -9 $pid
    done

    return 0
}


#nuke "symagent start"

killall -9 symagent
killall -9 nmap

/etc/init.d/symagent stop
sleep 3
/etc/init.d/symagent start
