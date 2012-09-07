#!/bin/sh

XVFB=`which Xvfb`
DISPLAY=:99 

if [ "$?" -eq 1 ];
  then
  echo "Xvfb not found."
exit 1
fi

FIREFOX=firefox-bin
if [ "$?" -eq 1 ];
  then
  echo "Firefox not found."
exit 1
fi

# launch virtual framebuffer into the background
$XVFB $DISPLAY -ac 2>/dev/null &    
# take the process ID
PID_XVFB="$!"      

# run the tests
if [ -z "$1" ];
  then
  FILTER=
else
  FILTER="-f $1"
fi

#run tests
cfx test $FILTER --binary-args="--display=$DISPLAY" 

# shut down xvfb (firefox will shut down cleanly by JsTestDriver)
kill $PID_XVFB     


