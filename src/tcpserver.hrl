-ifndef(TCPSERVER_HRL).

-include_lib("kernel/include/inet.hrl").
-include_lib("kernel/src/inet_dns.hrl").

-define(TCPSERVER_HRL, 1).
-define(TCP_OPTIONS, [binary, {packet, 0}, {active, false}, {reuseaddr, true}]).
-define(IDENT_PORT, 113).
-define(RULES_WATCHER_INTERVAL, 60000). % 60 seconds
-define(LOG, io:format).
-define(ERROR, 1).
-define(INFO, 2).

-record(state, {options, verbosity, rules, rules_ts, default_diemsgs}).
-record(peer, {ip, port, host, info}).
-record(connection, {local, remote}).
-record(rule, {address, action, vars, limits, diemsgs}).
-record(limits, {maxconnip, maxconnc, maxload}).
-record(diemsgs, {common, maxconnip, maxconnc, maxload}).

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
