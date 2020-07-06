#!/bin/sh
# Name: dt_start_estserver2.sh
#
# Purpose: Start estserver for use with Java EST Client testing

# usage:  <script_name> <port>
echo "Starting dt_start_estserver2.sh ..."

echo There are $# arguments to $0: $*
echo first arguement will be used as the port number = $1

cd $WORKSPACE/example/server

# this is the main estserver instance that should be used for simple reenrolls
$WORKSPACE/install/bin/estserver -o -p $1 --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 &
sleep 3

echo "dt_start_estserver2.sh is complete..."
exit 0
