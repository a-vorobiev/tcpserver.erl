-module(tcpserver).
-export([main/1]).
-include("tcpserver.hrl").

-define(MAX_CON, 3).

usage() ->
	?LOG("Usage: tcpserver [-1UXpPhHrRoOdDqQv] [-x <rules.cdb>] [-B <banner>] [-c <limit>] [-b <backlog>] [-g <gid>] [-u <uid>] [-l <localname>] [-t <timeout>] <host> <port> <program>~n"),
	halt(1).

main([]) ->
	usage();

main(RawArgs) ->
	{Options, Args} = parse_args(RawArgs),
	?LOG("Options: ~p~nNon-options: ~p~n", [Options, Args]),
	?LOG("~p~n", [proplists:get_keys(Options)]),
	?LOG("~p~n", [proplists:get_value(host, Options)]),
	?LOG("~p~n", [proplists:get_value(port, Options)]),

	% check if all required options are present
	[
		case proplists:get_value(Param, Options) of
			undefined ->
				usage();
			_ ->
				ok
		end
	|| Param <- [port, host, program]
	],

	RulesFile = proplists:get_value(rules, Options),

	if
		RulesFile /= undefined ->
			case tcprules:parse_file(RulesFile) of
				error ->
					Rules = [],
					halt(1);
				Rules ->
					ok
			end;
		true ->
			Rules = []
	end,


	start(#state{options = Options, args = Args, rules = Rules}).


parse_args(RawArgs) ->
	OptSpecList = option_spec_list(),
	case getopt:parse(OptSpecList, RawArgs) of
		{ok, Args} ->
			Args;
		{error, {Reason, Data}} ->
			?LOG("Error: ~s ~p~n~n", [Reason, Data]),
			halt(1)
	end.

start(S) ->
	Port = proplists:get_value(port, S#state.options),
	%check hostname/ip address
	%inet_parse:address
	Host = proplists:get_value(host, S#state.options),
	IP = case inet:gethostbyname(Host, inet) of
		{ok, {hostent, _, _, inet, 4, [ Val ]}} ->
			Val;
		Msg ->
			?LOG("Cannot use ~p as a host: ~p~n", [Host, Msg]),
			usage()
	end,
	Backlog = proplists:get_value(backlog, S#state.options),
	Limit = proplists:get_value(limit, S#state.options),

	case proplists:get_value(nodelay, S#state.options) of
		true ->
			TCPOptions = ?TCP_OPTIONS ++ [{ip, IP}, {backlog, Backlog}, {nodelay, true}];
		_ ->
			TCPOptions = ?TCP_OPTIONS ++ [{ip, IP}, {backlog, Backlog}]
	end,

	case gen_tcp:listen(Port, TCPOptions) of
		{ok, LSocket} ->
			register(connection_controller, spawn(fun() -> connection_counter(0, Limit, 0) end)),
			register(acceptor, spawn(fun() -> acceptor(LSocket, S) end)),
			sleep(infinity);
%			acceptor(LSocket, S);
		{error, eaddrnotavail} ->
			?LOG("Cannot listen on ~p~n", [proplists:get_value(host, S#state.options)]),
			halt(1);
		{error, eacces} ->
			?LOG("No premissions to listen on port ~p on ~p~n", [proplists:get_value(port, S#state.options),
										  proplists:get_value(host, S#state.options)]),
			halt(1)
%%		{Msg} ->
%%			log Msg
	end.

connection_counter(Count, Max, Pending) ->
	receive
		{From, may_i} ->
			?LOG("~p asks for accept permission; connection count: ~p~n", [From, Count]),
			verify_connection(From, Count, Max, Pending);
		{_, done} ->
			?LOG("Connection closed, count ~p~n", [Count - 1]),
			?LOG("Here we can check pending accepts and send them permission~n"),
			case Pending of
				0 ->
					connection_counter(Count - 1, Max, Pending);
				Val ->
					acceptor ! permission,
					?LOG("Permission sent to acceptor ~p~n", [acceptor]),
					connection_counter(Count, Max, Val - 1)
			end
	end.

verify_connection(From, Max, Max, Pending) ->
	From ! overloaded,
	?LOG("~p will be added to pending list~n", [From]),
	connection_counter(Max, Max, Pending + 1);

verify_connection(From, Count, Max, Pending) ->
	From ! ok,
	connection_counter(Count + 1, Max, Pending).

acceptor(LSocket, S) ->

%%	ask for new rules
%%	get answer and new rules if needed

	connection_controller ! {self(), may_i},
	receive
		ok ->
			?LOG("Recieved OK from controller, going on~n");
		overloaded ->
			?LOG("~p: we are overloaded, have to wait for permission~n", [self()]),
			% receive here??
			receive permission ->
				?LOG("Got permission~n"),
				ok
			end
	end,
	case gen_tcp:accept(LSocket) of
		{ok, Socket} ->
			ConnectionInfo = get_connection_info(Socket, S),
			case check_rules(S, ConnectionInfo) of
				allow ->
					io:format("ConnectionInfo = ~p~n", [ConnectionInfo]),
					case proplists:get_value(ip_dontroute, S#state.options) of
						true ->
							io:format("IP settings overrided~n"),
							inet:setopts(Socket, [{dontroute, true}]);
						_ ->
							ip_as_is
					end,

					Pid = spawn(fun() -> handle_connection(Socket, S) end),
					gen_tcp:controlling_process(Socket, Pid),
					Pid ! go,
					acceptor(LSocket, S);
				deny ->
					gen_tcp:close(Socket),
					connection_controller ! {self(), done}
			end;
		{error, econnaborted} ->
			acceptor(LSocket, S);
		{error, closed} ->
			connection_controller ! {self(), done},
			closed
%%		{Msg} ->
%%			log Msg
	end.

%%%
%%% tcpserver looks for rules with various addresses:
%%%
%%% 1. $TCPREMOTEINFO@$TCPREMOTEIP, if $TCPREMOTEINFO is set;
%%% 2. $TCPREMOTEINFO@=$TCPREMOTEHOST, if $TCPREMOTEINFO is set and $TCPREMOTEHOST is set;
%%% 3. $TCPREMOTEIP;
%%% 4. =$TCPREMOTEHOST, if $TCPREMOTEHOST is set;
%%% 5. shorter and shorter prefixes of $TCPREMOTEIP ending with a dot;
%%% 6. shorter and shorter suffixes of $TCPREMOTEHOST starting with a dot, preceded by =, if $TCPREMOTEHOST is set;
%%% 7. =, if $TCPREMOTEHOST is set; and finally
%%% 8. the empty string.
%%%
%%% http://cr.yp.to/ucspi-tcp/tcprules.html
%%%

check_rules(S, C) ->
	io:format("ConnectionInfo = ~p~n", [C]),
	RemoteIP = inet_parse:ntoa(C#connection.remote#peer.ip),
%	io:format("RemoteIP = ~p~n", [RemoteIP]),
	case tcprules:check_full_rules(RemoteIP, S#state.rules) of
		{rule, deny, _, _} ->
			deny;
		{rule, allow, _, Environment} ->
			allow;
		not_found ->
			io:format("full rule not found for ~p~n", [RemoteIP]),
			case tcprules:check_full_rules(C#connection.remote#peer.host, S#state.rules) of
				{rule, deny, _, _} ->
					deny;
				{rule, allow, _, Environment} ->
					allow;
				not_found ->
					io:format("full rule not found for ~p~n", [C#connection.remote#peer.host]),
					IP_Octets = lists:sublist(string:tokens(RemoteIP, "."), 3),
					case tcprules:check_network_rules(IP_Octets, 3, S#state.rules) of
						{rule, deny, _, _} ->
							deny;
						{rule, allow, _, Environment} ->
							allow;
						not_found ->
							io:format("network rule not found for ~p~n", [C#connection.remote#peer.host]),
							{Domain, Length} = get_domain(C#connection.remote#peer.host),
							io:format("Domain: ~p~n", [Domain]),
							case tcprules:check_name_rules(Domain, Length, S#state.rules) of
								{rule, deny, _, _} ->
									deny;
								{rule, allow, _, Environment} ->
									allow;
								not_found ->
									io:format("name rule not found for ~p~n", [C#connection.remote#peer.host]);
									% find empty rule here
								Val ->
									io:format("Unknown rule result: ~p~n", [Val])
							end;
						Val ->
							io:format("Unknown rule result: ~p~n", [Val])
					end;
				Val ->
					io:format("Unknown rule result: ~p~n", [Val])
			end;
		Val ->
			io:format("Unknown rule result: ~p~n", [Val])
	end,
	allow.

get_domain(undefined) ->
	{undefined, 0};

get_domain(Address) ->
	Domain = lists:nthtail(1, string:tokens(Address, ".")),
	Length = string:len(Domain),
	{Domain, Length}.


get_connection_info(Socket, S) ->

	LocalInfo = undefined,
	RemoteInfo = undefined,

	case inet:sockname(Socket) of
		{ok, {LocalIP, LocalPort}} ->

			LocalNameOption = proplists:get_value(localname, S#state.options),

			if
				LocalNameOption /= undefined ->
					LocalHost = LocalNameOption;
				true ->
					case inet:gethostbyaddr(LocalIP) of
						{ok, #hostent{h_name = LocalHost}} ->
							ok;
						{error, LocalHostErrMsg}->
							LocalHost = undefined,
							io:format("Can't get local hostname: ~p~n", [LocalHostErrMsg])
					end
			end;


		{error, LocalErrMsg} ->
			LocalIP = undefined,
			LocalHost = undefined,
			LocalPort = undefined,
			io:format("Can't get socket info: ~p~n", [LocalErrMsg])
	end,

	case inet:peername(Socket) of
		{ok, {RemoteIP, RemotePort}} ->

			case proplists:get_value(donot_lookup, S#state.options) of
				true ->
					RemoteHost = undefined;

				_ ->
					case inet:gethostbyaddr(RemoteIP) of
						{ok, #hostent{h_name = RemoteHostCandidate}} ->
							case proplists:get_value(not_paranoid, S#state.options) of
								true ->
									RemoteHost = RemoteHostCandidate;
								_ ->
									case inet:gethostbyname(RemoteHostCandidate) of
										{ok, RemoteHostent} ->
											case search_ip(RemoteIP, RemoteHostent#hostent.h_addr_list) of
												true ->
													RemoteHost = RemoteHostCandidate,
													io:format("Hostname ~p resolved back successfuly~n", [RemoteHostCandidate]);
												_ ->
													RemoteHost = undefined
											end;
										{error, RemoteHostResolveErr} ->
											io:format("RemoteHostResolvErr for ~p:~p~n", [RemoteHostCandidate, RemoteHostResolveErr]),
											RemoteHost = undefined
									end
							end;

						{error, RemoteHostErrMsg}->
							RemoteHost = undefined,
							io:format("Can't get remote hostname: ~p~n", [RemoteHostErrMsg])
					end
			end;


		{error, RemoteErrMsg} ->
			RemoteIP = undefined,
			RemotePort = undefined,
			RemoteHost = undefined,
			io:format("Can't get socket info: ~p~n", [RemoteErrMsg])
	end,

	#connection{local = #peer{ip = LocalIP, port = LocalPort, host = LocalHost, info = LocalInfo},
		    remote = #peer{ip = RemoteIP, port = RemotePort, host = RemoteHost, info = RemoteInfo}}.



search_ip(IP, []) ->
	false;

search_ip(IP, [IP|Tail]) ->
	true;

search_ip(IP, [IP|Tail]) ->
	search_ip(IP, Tail).


handle_connection(Socket, S) ->
	receive
		go ->
			inet:setopts(Socket, [{active, true}]),
			process_flag(trap_exit, true),
			Port = open_port({spawn, proplists:get_value(program, S#state.options)}, [stream, exit_status, binary]),
			?LOG("Going into connection loop~n"),
			Banner = proplists:get_value(banner, S#state.options),
			case Banner of
				undefined ->
					skip;
				_ ->
					gen_tcp:send(Socket, Banner)
			end,
			connection_loop(Socket, Port, S)
%%	after XXX ->
%%		timeout
	end.

connection_loop(Socket, Port, S) ->
	receive
		{tcp, Socket, Data} ->
			port_command(Port, Data),
			connection_loop(Socket, Port, S);
		{tcp_closed, Socket} ->
			connection_controller ! {self(), done},
			port_close(Port); %% more debug here
		{Port, {data, Response}} ->
			gen_tcp:send(Socket, Response),
			connection_loop(Socket, Port, S);
		{Port, {exit_status, _Status}} ->
%			?LOG("~p exited with status ~p~n", [Port, _Status]),
			connection_controller ! {self(), done},
			gen_tcp:close(Socket);
		{'EXIT', Port, _} ->
			connection_controller ! {self(), done},
			gen_tcp:close(Socket);
		{Port, Msg} ->
			?LOG("Unrouted message from ~p: ~p~n", [Port, Msg])
	end.


option_spec_list() ->
	[
		%% {Name,	ShortOpt,	LongOpt,	ArgSpec,	HelpMsg}
		{rules,		$x,		"rules",	string,		""},
		{banner,	$B,		"banner",	string,		""},
		{limit,		$c,		"limit",	{integer, 40},	""},
		{backlog,	$b,		"backlog",	{integer, 20},	""},
		{gid,		$g,		"gid",		string,		""}, %% not implemented yet
		{uid,		$u,		"uid",		string,		""}, %% not implemented yet
		{localname,	$l,		"localname",	string,		""},
		{timeout,	$t,		"timeout",	integer,	""}, %% not implemented yet

		{host,		undefined,	undefined,	string,		""},
		{port,		undefined,	undefined,	integer,	""},
		{program,	undefined,	undefined,	string,		""},

		{print_port,	$1,		undefined,	undefined,	""}, %% not implemented yet
		{envgiduid,	$U,		undefined,	undefined,	""}, %% not implemented yet
		{rules_missing,	$X,		undefined,	undefined,	""}, %% not implemented yet
		{paranoid,	$p,		undefined,	undefined,	""},
		{not_paranoid,	$P,		undefined,	undefined,	""},
		{remote_lookup,	$h,		undefined,	undefined,	""},
		{donot_lookup,	$H,		undefined,	undefined,	""},
		{get_info,	$r,		undefined,	undefined,	""}, %% not implemented yet
		{ignore_info,	$R,		undefined,	undefined,	""}, %% not implemented yet
		{ip_as_is,	$o,		undefined,	undefined,	""},
		{ip_dontroute,	$O,		undefined,	undefined,	""},
		{delay,		$d,		undefined,	undefined,	""},
		{nodelay,	$D,		undefined,	undefined,	""},
		{quiet,		$q,		undefined,	undefined,	""}, %% not implemented yet
		{err_only,	$Q,		undefined,	undefined,	""}, %% not implemented yet
		{verbose,	$v,		undefined,	undefined,	""}  %% not implemented yet
	].
