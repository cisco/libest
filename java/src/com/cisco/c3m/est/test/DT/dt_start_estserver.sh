#!/bin/sh
# Name: dt_start_estserver.sh

echo "Starting dt_start_estserver.sh ..."

cd $WORKSPACE/example/server

# this is the main estserver instance that should be used for simple enrolls
$WORKSPACE/install/bin/estserver -o -p $EST_DT0_PORT1  --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 &
sleep 1
# the following estserver is set to reject the first attempted connection so we can test catching exceptions
$WORKSPACE/install/bin/estserver    -p $EST_DT0_PORT2  --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 -m 3600 &
sleep 1
# this estserver should be started with -h to cause it to request and accept http digest authentication 
$WORKSPACE/install/bin/estserver -h -p $EST_DT0_DIGEST --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 &
sleep 1
# this is the estserver instance without "-o" that should be used for simple enrolls that use http authentication
$WORKSPACE/install/bin/estserver    -p $EST_DT0_PORT3  --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 &
sleep 1

echo "dt_start_estserver.sh is complete..."
exit 0
