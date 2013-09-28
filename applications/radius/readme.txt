This is a drop in replacement for jonny5 which uses a radius server for
authentication and accounting. The authentication and accounting use the
domain of the account as the user name, hence all sip accounts within a domain
use a single account on the radius server. The password for the radius account
is the Kazoo account id. The authentication is performed at the beginning of
a call and is intended for blocking calls without credit, or otherwise disabled
on the radius server.

To configure, add a document into the system_config called radius, and add
an array of servers, with IP address, port (authentication - accounting is
authentication port + 1) and shared secret. 

{
   "_id": "radius",
   "_rev": "4-5701c6eb4cf78c8cd44f3161c5c46636",
   "server": [
       {
           "ip": "x.y.z.1",
           "port": 1812,
           "secret": "sddsIjS9M"
       }
   ]
}

Change the system_config -> ecallmgr -> authz_enabled to true to enable.

This application uses digest authentication, with standard AV Pairs, with
a hardcoded nonce.
