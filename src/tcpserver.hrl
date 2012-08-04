-ifndef(TCPSERVER_HRL).

-include_lib("kernel/include/inet.hrl").

-define(TCPSERVER_HRL, 1).
-define(TCP_OPTIONS, [binary, {packet, 0}, {active, false}, {reuseaddr, true}]).
-define(LOG, io:format).
-define(ERROR, 1).
-define(INFO, 2).

-record(state, {options, verbosity, rules}).
-record(peer, {ip, port, host, info}).
-record(connection, {local, remote}).

sleep(T) ->
	receive
		after T ->
			ok
	end.

log(Verbosity, RecordVerbosity, String, Params) when RecordVerbosity =< Verbosity ->
	io:format(String ++ "~n", Params);

log(_, _, _, _) ->
	skipped.

-endif.
