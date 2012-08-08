tcpserver.erl
=============

This is an Erlang rewrite of [tcpserver](http://cr.yp.to/ucspi-tcp/tcpserver.html) by D.J.Bernstein.
Made as a first step of complete Qmail rewrite.


Build and usage
---------------
Build tcpserver by *make* command. You need to have path to *erlc* in your *PATH* environment variable.
As a result you'll have a single *tcpserver* executable which accepts the same command line params as original tcpserver does (excpet -u, -g and -U):

````
Usage: tcpserver [-1XpPhHrRoOdDqQv] [-x <rules.txt>] [-B <banner>] [-c <limit>] [-b <backlog>] [-l <localname>] [-t <timeout>] <host> <port> <program>
````

Another difference is that rules file is raw text instead of cdb, tcpserver looks for changes in rules file once in a minute and loads new rules if there are any.
