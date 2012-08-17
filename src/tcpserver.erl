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

	DefaultDiemsgs = get_default_diemsgs(),

	{ok, _} = cpu_sup:start(),

	start(#state{options = FinalOptions, verbosity = Verbosity, rules = Rules, rules_ts = TS, default_diemsgs = DefaultDiemsgs}).

get_default_diemsgs() ->
	case os:getenv("DIEMSG") of
		false ->
			DieMsg = undefined;
		DieMsg ->
			go_on
	end,
	case os:getenv("DIEMSG_MAXLOAD") of
		false ->
			DieMsgMaxLoad = undefined;
		DieMsgMaxLoad ->
			go_on
	end,
	case os:getenv("DIEMSG_MAXCONNIP") of
		false ->
			DieMsgMaxConnIP = undefined;
		DieMsgMaxConnIP ->
			go_on
	end,
	case os:getenv("DIEMSG_MAXCONNC") of
		false ->
			DieMsgMaxConnC = undefined;
		DieMsgMaxConnC ->
			go_on
	end,
	#diemsgs{common = DieMsg, maxconnip = DieMsgMaxConnIP, maxconnc = DieMsgMaxConnC, maxload = DieMsgMaxLoad}.

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
			register(connection_guard, spawn(fun() -> connection_guard(S, 0, Limit, 0, dict:new()) end)),
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

connection_guard(S, Count, Max, Pending, Connections) ->
	receive
		{From, may_i} ->
			log(S#state.verbosity, ?INFO, "~p asks for accept permission; connection count: ~p", [From, Count]),
			verify_connection(S, From, Count, Max, Pending, Connections);
		{From, check_limits, R, C} ->
			case verify_limits(R#rule.limits, C#connection.remote#peer.ip, Connections) of
				allow ->
					From ! allow,
					NewConnections = dict:update_counter(C#connection.remote#peer.ip, 1, Connections);
				{deny, Reason} ->
					From ! {deny, Reason},
					NewConnections = Connections
			end,
			connection_guard(S, Count, Max, Pending, NewConnections);
		{_, done} ->
			proceed_pending_connections(S, Count, Max, Pending, Connections);
		{_, done, IP} ->
			proceed_pending_connections(S, Count, Max, Pending, dict:update_counter(IP, -1, Connections))
	end.

proceed_pending_connections(S, Count, Max, Pending, Connections) ->
	case Pending of
		0 ->
			connection_guard(S, Count - 1, Max, Pending, Connections);
		Val ->
			acceptor ! permission,
			connection_guard(S, Count, Max, Val - 1, Connections)
	end.

verify_limits(L, IP, Connections) ->
	case L#limits.maxload of
		MaxLoad when is_integer(MaxLoad) ->
			Avg1 = cpu_sup:avg1() / 256 * 100,
			if
				Avg1 >= L#limits.maxload ->
					{deny, maxload};
				true ->
					verify_connip(L, IP, Connections)
			end;
		undefined ->
			verify_connip(L, IP, Connections)
	end.

verify_connip(L, IP, Connections) ->
	case L#limits.maxconnip of
		MaxConnIP when is_integer(MaxConnIP) andalso MaxConnIP > 0 ->
			case dict:find(IP, Connections) of
				{ok, Value} when is_integer(Value) andalso Value >= MaxConnIP ->
					{deny, maxconnip};
				_ ->
					verify_connc(L, IP, Connections)
			end;
		MaxConnIP when is_integer(MaxConnIP) ->
			{deny, maxconnip};
		undefined ->
			verify_connc(L, IP, Connections)
	end.

verify_connc(L, IP, Connections) ->
	case L#limits.maxconnc of
		MaxConnC when is_integer(MaxConnC) ->
			ConnC = dict:size(dict:filter(fun(K, V) -> {A,B,C,_} = IP, case K of {A,B,C,_} when V > 0 -> true; _ -> false end end, Connections)),
			if
				ConnC >= MaxConnC ->
					{deny, maxconnc};
				true ->
					allow
			end;
		undefined ->
			allow
	end.

verify_connection(S, From, Max, Max, Pending, Connections) ->
	From ! overloaded,
	connection_guard(S, Max, Max, Pending + 1, Connections);

verify_connection(S, From, Count, Max, Pending, Connections) ->
	From ! ok,
	connection_guard(S, Count + 1, Max, Pending, Connections).

acceptor(LSocket, S) ->
	connection_guard ! {self(), may_i},
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
				#rule{action = allow} = R ->
					case proplists:get_value(ip_dontroute, S#state.options) of
						true ->
							inet:setopts(Socket, [{dontroute, true}]);
						_ ->
							ip_as_is
					end,
					connection_guard ! {self(), check_limits, R, ConnectionInfo},
					receive
						allow ->
							Pid = spawn(fun() -> handle_connection(Socket, NewS, R#rule.vars, ConnectionInfo) end),
							gen_tcp:controlling_process(Socket, Pid),
							Pid ! go,
							acceptor(LSocket, NewS);
						{deny, Reason} ->
							sleep(1000),
							case Reason of
								maxconnip ->
									case get_diemsg(S, R, maxconnip) of
										undefined ->
											skip;
										Msg ->
											log(S#state.verbosity, ?INFO, "Connection from ~p denied: MAXCONNIP", [ConnectionInfo#connection.remote#peer.ip]),
											gen_tcp:send(Socket, Msg ++ "\r\n")
									end;
								maxconnc ->
									case get_diemsg(S, R, maxconnc) of
										undefined ->
											skip;
										Msg ->
											log(S#state.verbosity, ?INFO, "Connection from ~p denied: MAXCONNC", [ConnectionInfo#connection.remote#peer.ip]),
											gen_tcp:send(Socket, Msg ++ "\r\n")
									end;
								maxload ->
									case get_diemsg(S, R, maxload) of
										undefined ->
											skip;
										Msg ->
											log(S#state.verbosity, ?INFO, "Connection from ~p denied: MAXLOAD", [ConnectionInfo#connection.remote#peer.ip]),
											gen_tcp:send(Socket, Msg ++ "\r\n")
									end;
								_ ->
									log(S#state.verbosity, ?ERROR, "Unknown reason for denial: ~p", [Reason])
							end,
							gen_tcp:close(Socket),
							connection_guard ! {self(), done},
							acceptor(LSocket, S)
					end;
				#rule{action = deny} ->
					gen_tcp:close(Socket),
					connection_guard ! {self(), done, ConnectionInfo#connection.remote#peer.ip},
					acceptor(LSocket, S)
			end;
		{error, econnaborted} ->
			acceptor(LSocket, S);
		{error, closed} ->
			connection_guard ! {self(), done},
			closed
%%		{Msg} ->
%%			log Msg
	end.

get_diemsg(S, R, Limit) ->
	case Limit of
		maxconnip ->
			case R#rule.diemsgs#diemsgs.maxconnip of
				undefined->
					case S#state.default_diemsgs#diemsgs.maxconnip of
						undefined ->
							case R#rule.diemsgs#diemsgs.common of
								undefined ->
									S#state.default_diemsgs#diemsgs.common;
								Msg ->
									Msg
							end;
						Msg ->
							Msg
					end;
				Msg ->
					Msg
			end;
		maxconnc ->
			case R#rule.diemsgs#diemsgs.maxconnc of
				undefined->
					case S#state.default_diemsgs#diemsgs.maxconnc of
						undefined ->
							case R#rule.diemsgs#diemsgs.common of
								undefined ->
									S#state.default_diemsgs#diemsgs.common;
								Msg ->
									Msg
							end;
						Msg ->
							Msg
					end;
				Msg ->
					Msg
			end;
		maxload->
			case R#rule.diemsgs#diemsgs.maxload of
				undefined->
					case S#state.default_diemsgs#diemsgs.maxload of
						undefined ->
							case R#rule.diemsgs#diemsgs.common of
								undefined ->
									S#state.default_diemsgs#diemsgs.common;
								Msg ->
									Msg
							end;
						Msg ->
							Msg
					end;
				Msg ->
					Msg
			end
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
	try_info_rules(S, C, RemoteIP).

try_info_rules(S, C, RemoteIP) ->
	case tcprules:check_info_rules(C#connection.remote#peer.info, RemoteIP, S#state.rules) of
		Value when is_record(Value, rule) ->
			Value;
		not_found ->
			case tcprules:check_info_rules(C#connection.remote#peer.info, C#connection.remote#peer.host, S#state.rules) of
				Value when is_record(Value, rule) ->
					Value;
				not_found ->
					try_full_rules(S, C, RemoteIP);
				Unknown ->
					log(S#state.verbosity, ?ERROR, "Unknown check_info_rules result: ~p", [Unknown]),
					#rule{action = deny}
			end;
		Unknown ->
			log(S#state.verbosity, ?ERROR, "Unknown check_info_rules result: ~p", [Unknown]),
			#rule{action = deny}
	end.


try_full_rules(S, C, RemoteIP) ->
	case tcprules:check_full_rules(RemoteIP, S#state.rules) of
		Value when is_record(Value, rule) ->
			Value;
		not_found ->
			case tcprules:check_full_rules(C#connection.remote#peer.host, S#state.rules) of
				Value when is_record(Value, rule) ->
					Value;
				not_found ->
					try_subnet_rules(S, C, RemoteIP);
				Unknown ->
					log(S#state.verbosity, ?ERROR, "Unknown check_full_rules result: ~p", [Unknown]),
					#rule{action = deny}
			end;
		Unknown ->
			log(S#state.verbosity, ?ERROR, "Unknown check_full_rules result: ~p", [Unknown]),
			#rule{action = deny}
	end.

try_subnet_rules(S, C, RemoteIP) ->
	Subnet = lists:sublist(string:tokens(RemoteIP, "."), 3),
	case tcprules:check_network_rules(Subnet, 3, S#state.rules) of
		Value when is_record(Value, rule) ->
			Value;
		not_found ->
			try_domain_rules(S, C);
		Unknown ->
			log(S#state.verbosity, ?ERROR, "Unknown check_network_rules result: ~p", [Unknown]),
			#rule{action = deny}
	end.

try_domain_rules(S, C) ->
	{Domain, Length} = get_domain(C#connection.remote#peer.host),
	case tcprules:check_name_rules(Domain, Length, S#state.rules) of
		Value when is_record(Value, rule) ->
			Value;
		not_found ->
			try_empty_rules(S);
		Unknown ->
			log(S#state.verbosity, ?ERROR, "Unknown check_domain_rules result: ~p", [Unknown]),
			#rule{action = deny}
	end.

try_empty_rules(S) ->
	case tcprules:check_empty_rules(S#state.rules) of
		Value when is_record(Value, rule) ->
			Value;
		not_found ->
			#rule{action=deny};
		Unknown ->
			log(S#state.verbosity, ?ERROR, "Unknown check_empty_rules result: ~p", [Unknown]),
			#rule{action = deny}
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

handle_connection(Socket, S, EnvVars, C) ->
	receive
		go ->
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
			connection_loop(Socket, Port, S, C)
%%	after XXX ->
%%		timeout
	end.

ip2str(IP) ->
	case IP of
		{_, _, _, _} ->
			inet_parse:ntoa(IP);
		_ ->
			undefined
	end.

connection_loop(Socket, Port, S, C) ->
	receive
		{tcp, Socket, Data} ->
			port_command(Port, Data),
			connection_loop(Socket, Port, S, C);
		{tcp_closed, Socket} ->
			connection_guard ! {self(), done, C#connection.remote#peer.ip},
			port_close(Port); %% more debug here
		{Port, {data, Response}} ->
			gen_tcp:send(Socket, Response),
			connection_loop(Socket, Port, S, C);
		{Port, {exit_status, _Status}} ->
			log(S#state.verbosity, ?INFO, "~p exited with status ~p", [Port, _Status]),
			connection_guard ! {self(), done, C#connection.remote#peer.ip},
			gen_tcp:close(Socket);
		{'EXIT', Port, _} ->
			connection_guard ! {self(), done, C#connection.remote#peer.ip},
			gen_tcp:close(Socket);
		{Port, Msg} ->
			log(S#state.verbosity, ?ERROR, "Unrouted message from ~p: ~p", [Port, Msg]);
		Msg ->
			log(S#state.verbosity, ?ERROR, "Unknown message: ~p", [Msg])
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
