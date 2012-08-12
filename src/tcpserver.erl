-module(tcpserver).
-export([main/1]).
-include("tcpserver.hrl").

usage() ->
	?LOG("Usage: tcpserver [-1XpPhHrRoOdDqQv] [-x <rules.txt>] [-B <banner>] [-c <limit>] [-b <backlog>] [-l <localname>] [-t <timeout>] <host> <port> <program>~n"),
	halt(1).

main([]) ->
	usage();

main(RawArgs) ->
	{Options, Args} = parse_args(RawArgs),
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
					TS = 0,
					halt(1);
				Rules ->
					TS = tcprules:check_file_ts(RulesFile),
					ok
			end;
		true ->
			Rules = [],
			TS = 0
	end,

	register(rules_watcher, spawn(fun() -> tcprules:watcher(RulesFile, ?RULES_WATCHER_INTERVAL, Rules) end)),

	Verbosity = case proplists:get_value(quiet, Options) of
		true ->
			0;
		_ ->
			case proplists:get_value(verbose, Options) of
				true ->
					2;
				_ ->
					1
			end
	end,

	FinalOptions = case Args of
		[] ->
			Options;
		_ ->
			Program = proplists:get_value(program, Options) ++ " " ++ string:join(Args, " "),
			proplists:delete(program, Options) ++ [{program, Program}]
	end,

	start(#state{options = FinalOptions, verbosity = Verbosity, rules = Rules, rules_ts = TS}).


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
			register(connection_controller, spawn(fun() -> connection_counter(S, 0, Limit, 0) end)),
			register(acceptor, spawn(fun() -> acceptor(LSocket, S) end)),
			sleep(infinity);
		{error, eaddrnotavail} ->
			log(S#state.verbosity, ?ERROR, "Cannot listen on ~p", [proplists:get_value(host, S#state.options)]),
			halt(1);
		{error, eacces} ->
			log(S#state.verbosity, ?ERROR, "No premission to listen on port ~p on ~p", [proplists:get_value(port, S#state.options),
												    proplists:get_value(host, S#state.options)]),
			halt(1);
		{ListenErrMsg} ->
			log(S#state.verbosity, ?ERROR, "Error while listening on ~p:~p (~p)", [IP, Port, ListenErrMsg])
	end.

connection_counter(S, Count, Max, Pending) ->
	receive
		{From, may_i} ->
			log(S#state.verbosity, ?INFO, "~p asks for accept permission; connection count: ~p", [From, Count]),
			verify_connection(S, From, Count, Max, Pending);
		{_, done} ->
			case Pending of
				0 ->
					connection_counter(S, Count - 1, Max, Pending);
				Val ->
					acceptor ! permission,
					connection_counter(S, Count, Max, Val - 1)
			end
	end.

verify_connection(S, From, Max, Max, Pending) ->
	From ! overloaded,
	connection_counter(S, Max, Max, Pending + 1);

verify_connection(S, From, Count, Max, Pending) ->
	From ! ok,
	connection_counter(S, Count + 1, Max, Pending).

acceptor(LSocket, S) ->
	connection_controller ! {self(), may_i},
	receive
		ok ->
			go_on;
		overloaded ->
			receive permission ->
				go_on
			end
	end,

	case gen_tcp:accept(LSocket) of
		{ok, Socket} ->
			ConnectionInfo = get_connection_info(Socket, S),
			rules_watcher ! {new_rules, self(), S#state.rules_ts},
			receive
				no_new_rules ->
					NewS = S;
				{new_rules, NewTS, NewRules} ->
					NewS = #state{options = S#state.options, verbosity = S#state.verbosity, rules = NewRules, rules_ts = NewTS}
			end,
			case check_rules(NewS, ConnectionInfo) of
				{allow, Env} ->
					case proplists:get_value(ip_dontroute, S#state.options) of
						true ->
							inet:setopts(Socket, [{dontroute, true}]);
						_ ->
							ip_as_is
					end,
					Pid = spawn(fun() -> handle_connection(Socket, NewS, Env, ConnectionInfo) end),
					gen_tcp:controlling_process(Socket, Pid),
					Pid ! go,
					acceptor(LSocket, NewS);
				deny ->
					gen_tcp:close(Socket),
					connection_controller ! {self(), done},
					acceptor(LSocket, S)
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
	RemoteIP = inet_parse:ntoa(C#connection.remote#peer.ip),

	case tcprules:check_info_rules(C#connection.remote#peer.info, RemoteIP, S#state.rules) of
		{rule, deny, _, _} ->
			deny;
		{rule, allow, _, Environment} ->
			{allow, Environment};
		not_found ->
			case tcprules:check_info_rules(C#connection.remote#peer.info, C#connection.remote#peer.host, S#state.rules) of
				{rule, deny, _, _} ->
					deny;
				{rule, allow, _, Environment} ->
					{allow, Environment};
				not_found ->
					case tcprules:check_full_rules(RemoteIP, S#state.rules) of
						{rule, deny, _, _} ->
							deny;
						{rule, allow, _, Environment} ->
							{allow, Environment};
						not_found ->
							case tcprules:check_full_rules(C#connection.remote#peer.host, S#state.rules) of
								{rule, deny, _, _} ->
									deny;
								{rule, allow, _, Environment} ->
									{allow, Environment};
								not_found ->
									IP_Octets = lists:sublist(string:tokens(RemoteIP, "."), 3),
									case tcprules:check_network_rules(IP_Octets, 3, S#state.rules) of
										{rule, deny, _, _} ->
											deny;
										{rule, allow, _, Environment} ->
											{allow, Environment};
										not_found ->
											{Domain, Length} = get_domain(C#connection.remote#peer.host),
											case tcprules:check_name_rules(Domain, Length, S#state.rules) of
												{rule, deny, _, _} ->
													deny;
												{rule, allow, _, Environment} ->
													{allow, Environment};
												not_found ->
													case tcprules:check_empty_rules(S#state.rules) of
														{rule, allow, _, Environment} ->
															{allow, Environment};
														_ ->
															deny
													end;
												Val ->
													log(S#state.verbosity, ?ERROR, "Unknown check_name_rules result: ~p", [Val]),
													deny
											end;
										Val ->
											log(S#state.verbosity, ?ERROR, "Unknown check_network_rules result: ~p", [Val]),
											deny
									end;
								Val ->
									log(S#state.verbosity, ?ERROR, "Unknown check_full_rules result: ~p", [Val]),
									deny
							end;
						Val ->
							log(S#state.verbosity, ?ERROR, "Unknown check_full_rules result: ~p", [Val]),
							deny
					end;
				Val ->
					log(S#state.verbosity, ?ERROR, "Unknown check_info_rules result: ~p", [Val]),
					deny
			end;
		Val ->
			log(S#state.verbosity, ?ERROR, "Unknown check_info_rules result: ~p", [Val]),
			deny
	end.

get_domain(undefined) ->
	{undefined, 0};

get_domain(Address) ->
	Domain = lists:nthtail(1, string:tokens(Address, ".")),
	Length = string:len(Domain),
	{Domain, Length}.

get_connection_info(Socket, S) ->
	case inet:sockname(Socket) of
		{ok, {LocalIP, LocalPort}} ->
			LocalNameOption = proplists:get_value(localname, S#state.options),
			if
				LocalNameOption /= undefined ->
					LocalHost = LocalNameOption;
				true ->
					LocalHost = resolve_ptr(S, LocalIP)
			end;
		{error, LocalErrMsg} ->
			LocalIP = undefined,
			LocalHost = undefined,
			LocalPort = undefined,
			log(S#state.verbosity, ?ERROR, "Can't get socket info: ~p", [LocalErrMsg])
	end,

	case inet:peername(Socket) of
		{ok, {RemoteIP, RemotePort}} ->
			case proplists:get_value(donot_lookup, S#state.options) of
				true ->
					RemoteHost = undefined;
				_ ->
					RemoteHost = case resolve_ptr(S, RemoteIP) of
						undefined ->
							undefined;
						RemoteHostCandidate ->
							case proplists:get_value(not_paranoid, S#state.options) of
								true ->
									RemoteHostCandidate;
								_ ->
									case inet:gethostbyname(RemoteHostCandidate) of
										{ok, RemoteHostent} ->
											case search_ip(RemoteIP, RemoteHostent#hostent.h_addr_list) of
												true ->
													log(S#state.verbosity, ?INFO, "Hostname ~p resolved back successfuly", [RemoteHostCandidate]),
													RemoteHostCandidate;
												_ ->
													log(S#state.verbosity, ?INFO, "Could not resolve back ~p, TCPREMOTEHOST is undefined", [RemoteHostCandidate]),
													undefined
											end;
										{error, RemoteHostResolveErr} ->
											log(S#state.verbosity, ?ERROR, "RemoteHostResolvErr for ~p:~p", [RemoteHostCandidate, RemoteHostResolveErr]),
											undefined
									end
							end
					end
			end;
		{error, RemoteErrMsg} ->
			RemoteIP = undefined,
			RemotePort = undefined,
			RemoteHost = undefined,
			log(S#state.verbosity, ?ERROR, "Can't get socket info: ~p", [RemoteErrMsg])
	end,
	LocalInfo = local,
	case proplists:get_value(ignore_info, S#state.options) of
		true ->
			RemoteInfo = undefined;
		_ ->
			Timeout = proplists:get_value(info_timeout, S#state.options),
			case gen_tcp:connect(RemoteIP, ?IDENT_PORT, [{active, false}, {packet, 0}], Timeout) of
				{ok, IdentSock} ->
					IdentRequest = io_lib:format("~p , ~p\r\n", [RemotePort, LocalPort]),
					RemoteInfo = try gen_tcp:send(IdentSock, IdentRequest, Timeout) of
						ok ->
							try gen_tcp:recv(IdentSock, 0, Timeout) of
								{ok, IdentResponse} ->
									case re:run(IdentResponse, "^(.*):(.*)\r\n") of
										{match, [_, _, {Start, Length}]} ->
											string:substr(IdentResponse, Start + 1, Length);
										_ ->
											log(S#state.verbosity, ?ERROR, "Could not get RemoteInfo", []),
											undefined
									end
								catch IdentExc:IdentReason->
									log(S#state.verbosity, ?ERROR, "Error while communicating with ident server (~p: ~p)", [IdentExc, IdentReason]),
									undefined
							end
						catch _:_ ->
							undefined
					end,
					gen_tcp:close(IdentSock);
				_ ->
					RemoteInfo = undefined
			end
	end,
	#connection{local = #peer{ip = LocalIP, port = LocalPort, host = LocalHost, info = LocalInfo},
		    remote = #peer{ip = RemoteIP, port = RemotePort, host = RemoteHost, info = RemoteInfo}}.

resolve_ptr(S, IP) ->
	case inet_res:resolve(IP, any, ptr) of
		{ok, #dns_rec{anlist=[Answer|_]}} ->
			proplists:get_value(data, inet_dns:rr(Answer));
		{error, Reply} ->
			log(S#state.verbosity, ?ERROR, "Can't resolve ~p: ~p", [IP, Reply]),
			undefined;
		_ ->
			log(S#state.verbosity, ?ERROR, "Can't resolve ~p", [IP]),
			undefined
	end.

search_ip(_, []) ->
	false;

search_ip(IP, [IP|_]) ->
	true;

search_ip(IP, [_|Tail]) ->
	search_ip(IP, Tail).

handle_connection(Socket, S, Env, C) ->
	receive
		go ->
			EnvVars = [ extract_var(E) || E <- Env],
			RemoteIP = ip2str(C#connection.remote#peer.ip),
			LocalIP = ip2str(C#connection.local#peer.ip),
			LocalVars = [ {X, Y} || {X, Y} <- [{"TCPLOCALIP", LocalIP},
							   {"TCPLOCALHOST", C#connection.local#peer.host},
							   {"TCPLOCALPORT", integer_to_list(C#connection.local#peer.port)}], Y /= undefined],
			RemoteVars = [ {X, Y} || {X, Y} <- [{"TCPREMOTEIP", RemoteIP},
							    {"TCPREMOTEHOST", C#connection.remote#peer.host},
							    {"TCPREMOTEPORT", integer_to_list(C#connection.remote#peer.port)},
							    {"TCPREMOTEINFO", C#connection.remote#peer.info}], Y /= undefined],
			inet:setopts(Socket, [{active, true}]),
			process_flag(trap_exit, true),
			Port = open_port({spawn, proplists:get_value(program, S#state.options)}, [stream, exit_status, binary, {env, EnvVars ++ [{"PROTO", "TCP"}] ++ LocalVars ++ RemoteVars}]),
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

extract_var(Str) ->
	[Var, Val] = string:tokens(Str, "="),
	{Var, string:strip(Val, both, $")}.

ip2str(IP) ->
	case IP of
		{_, _, _, _} ->
			inet_parse:ntoa(IP);
		_ ->
			undefined
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
			log(S#state.verbosity, ?INFO, "~p exited with status ~p", [Port, _Status]),
			connection_controller ! {self(), done},
			gen_tcp:close(Socket);
		{'EXIT', Port, _} ->
			connection_controller ! {self(), done},
			gen_tcp:close(Socket);
		{Port, Msg} ->
			log(S#state.verbosity, ?ERROR, "Unrouted message from ~p: ~p", [Port, Msg])
	end.


option_spec_list() ->
	[
		%% {Name,	ShortOpt,	LongOpt,	ArgSpec,	HelpMsg}
		{rules,		$x,		"rules",	string,		""},
		{banner,	$B,		"banner",	string,		""},
		{limit,		$c,		"limit",	{integer, 40},	""},
		{backlog,	$b,		"backlog",	{integer, 20},	""},
%		{gid,		$g,		"gid",		string,		""}, %% not implementable
%		{uid,		$u,		"uid",		string,		""}, %% not implementable
		{localname,	$l,		"localname",	string,		""},
		{info_timeout,	$t,		"timeout",	{integer, 26},	""},

		{host,		undefined,	undefined,	string,		""},
		{port,		undefined,	undefined,	integer,	""},
		{program,	undefined,	undefined,	string,		""},

		{print_port,	$1,		undefined,	undefined,	""}, %% not implemented yet
		{envgiduid,	$U,		undefined,	undefined,	""}, %% not implementable
		{rules_missing,	$X,		undefined,	undefined,	""}, %% not implemented yet
		{paranoid,	$p,		undefined,	undefined,	""},
		{not_paranoid,	$P,		undefined,	undefined,	""},
		{remote_lookup,	$h,		undefined,	undefined,	""},
		{donot_lookup,	$H,		undefined,	undefined,	""},
		{get_info,	$r,		undefined,	undefined,	""},
		{ignore_info,	$R,		undefined,	undefined,	""},
		{ip_as_is,	$o,		undefined,	undefined,	""},
		{ip_dontroute,	$O,		undefined,	undefined,	""},
		{delay,		$d,		undefined,	undefined,	""},
		{nodelay,	$D,		undefined,	undefined,	""},
		{quiet,		$q,		undefined,	undefined,	""},
		{err_only,	$Q,		undefined,	undefined,	""},
		{verbose,	$v,		undefined,	undefined,	""}
	].
