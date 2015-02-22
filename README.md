# netscanner-slave
netscanner-slave is a distributed multihreaded network scanner I wrote for a personal project some years ago.

It works as a cli program which is able to:

1. Do on-call network scans to a given CIDR
2. Work as a daemon which gets targets from a master node and reports scan results to it

I am not releasing the master's code, because I'm not its author. However, it shouldn't be very hard to write your own if you want to. Just look at webgate.[ch]

## Dependencies
1. jansson http://www.digip.org/jansson/
2. libcidr https://github.com/wikimedia-incubator/libcidr