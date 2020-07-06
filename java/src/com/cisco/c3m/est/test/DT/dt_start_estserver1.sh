#!/bin/sh
# Name: dt_start_estserver1.sh
# For use with ESTClientTest.java and ESTClientTestNonFIPS.java tests
# and uses four instances of estserver

# usage:  <script_name> <port1> <port2> <port3> <port4>
echo "Starting dt_start_estserver1.sh ..."

cd $WORKSPACE/example/server

echo There are $# arguments to $0: $*
echo first arguement will be used as the port number = $1

# this is the main estserver instance that should be used for simple enrolls
$WORKSPACE/install/bin/estserver -o -p $1  --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 &
sleep 1
# the following estserver is set to reject the first attempted connection so we can test catching exceptions
$WORKSPACE/install/bin/estserver    -p $2  --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 -m 3600 &
sleep 1
# this estserver should be started with -h to cause it to request and accept http digest authentication 
$WORKSPACE/install/bin/estserver -h -p $3  --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 &
sleep 1
# this is the estserver instance without "-o" that should be used for simple enrolls that use http authentication
$WORKSPACE/install/bin/estserver    -p $4  --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 &
sleep 1

echo "dt_start_estserver1.sh is complete..."
exit 0
