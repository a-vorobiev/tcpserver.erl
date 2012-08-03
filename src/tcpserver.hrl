-ifndef(TCPSERVER_HRL).

-include_lib("kernel/include/inet.hrl").

-define(TCPSERVER_HRL, 1).
-define(TCP_OPTIONS, [binary, {packet, 0}, {active, false}, {reuseaddr, true}]).
-define(LOG, io:format).

-record(state, {options, args, rules}).
-record(peer, {ip, port, host, info}).
-record(connection, {local, remote}).

sleep(T) ->
	receive
		after T ->
			ok
	end.

-endif.
