-module(tcprules).
-export([parse_file/1, check_info_rules/3, check_full_rules/2, check_network_rules/3, check_name_rules/3, check_empty_rules/1, watcher/3, check_file_ts/1]).
-include_lib("kernel/include/file.hrl").
-include("tcpserver.hrl").

parse_file(RulesFile) ->
	case file:open(RulesFile, [read]) of
		{ok, Fd} ->
			for_each_line(Fd, fun parse/3, 1, []);
		{error, Reason} ->
			io:format("Cannot open ~p:~p~n", [RulesFile, Reason]),
			error
	end.

for_each_line(Fd, Proc, Count, Acc) ->
	case io:get_line(Fd, "") of
		eof ->
			file:close(Fd),
			Acc;
		Line ->
			NewAcc = Proc(Line, Count, Acc),
			for_each_line(Fd, Proc, Count + 1, NewAcc)
	end.

parse(Line, Count, Acc) ->
	case re:run(Line, "^\s*(#.*)?$") of % skip comments and empty lines
		{match, _} ->
			Acc;
		nomatch ->
			case re:run(Line, "^(.*):(allow|deny)([^#]*)[#|\n].*") of
				{match, Match} ->
					[_|Boundaries] = Match,
					Fields = lists:map( fun(X) ->
						{Start, Length} = X,
						string:substr(Line, Start + 1, Length)
					end, Boundaries),
					[Address, Action, EnvString] = Fields,
					EnvVars = [extract_var(E) || E <- string:tokens(string:strip(EnvString), ",")],
					[Limits, DieMsgs] = find_limits(EnvVars),
					Acc ++ [#rule{address = Address, action = list_to_atom(Action), vars = EnvVars, limits = Limits, diemsgs = DieMsgs}];
				_ ->
					io:format("Unknown rule in Line ~p: ~p~n", [Count, Line]),
					Acc
			end
	end.

find_limits(EnvVars) ->
	find_limits(#limits{}, #diemsgs{}, EnvVars).

find_limits(Limits, DieMsgs, []) ->
	[Limits, DieMsgs];

find_limits(Limits, DieMsgs, [EnvVar | Tail]) ->
	case EnvVar of
		{"MAXCONNIP", Value} ->
			find_limits(Limits#limits{maxconnip = list_to_integer(Value)}, DieMsgs, Tail);
		{"MAXCONNC", Value} ->
			find_limits(Limits#limits{maxconnc = list_to_integer(Value)}, DieMsgs, Tail);
		{"MAXLOAD", Value} ->
			find_limits(Limits#limits{maxload = list_to_integer(Value)}, DieMsgs, Tail);
		{"DIEMSG", Value} ->
			find_limits(Limits, DieMsgs#diemsgs{common = Value}, Tail);
		{"DIEMSG_MAXCONNIP", Value} ->
			find_limits(Limits, DieMsgs#diemsgs{maxconnip = Value}, Tail);
		{"DIEMSG_MAXCONNC", Value} ->
			find_limits(Limits, DieMsgs#diemsgs{maxconnc = Value}, Tail);
		{"DIEMSG_MAXLOAD", Value} ->
			find_limits(Limits, DieMsgs#diemsgs{maxload = Value}, Tail);
		_ ->
			find_limits(Limits, DieMsgs, Tail)
	end.

extract_var(Str) ->
	[Var, Val] = string:tokens(Str, "="),
	{string:strip(Var), string:strip(string:strip(Val), both, $")}.

check_info_rules(undefined, _, _) ->
	not_found;

check_info_rules(_, undefined, _) ->
	not_found;

check_info_rules(Info, Address, Rules) ->
	check_full_rules(Info ++ "@" ++ Address, Rules).

check_full_rules(undefined, _) ->
	not_found;

check_full_rules(_, []) ->
	not_found;

check_full_rules(Address, [Head|Tail]) ->
	case Head of
		#rule{address = Address} ->
			Head;
		_ ->
		check_full_rules(Address, Tail)
	end.

check_network_rules(undefined, _, _) ->
	not_found;

check_network_rules(Address, N, Rules) ->
	check_network_rules(Address, N, Rules, Rules).

check_network_rules(_, N, [], _) when N =< 1 ->
	not_found;

check_network_rules(Address, N, [], Rules) ->
	check_network_rules(lists:sublist(Address, N - 1), N - 1, Rules, Rules);

check_network_rules(Address, N, [Head|Tail], Rules) ->
	AddressPattern = string:join(Address,".") ++ [$.],
	case Head of
		#rule{address = AddressPattern} ->
			Head;
		_ ->
		check_network_rules(Address, N, Tail, Rules)
	end.

check_name_rules(undefined, _, _) ->
	not_found;

check_name_rules(Address, N, Rules) ->
	check_name_rules(Address, N, Rules, Rules).

check_name_rules(_, N, [], _) when N =< 1 ->
	not_found;

check_name_rules(Address, N, [], Rules) ->
	check_name_rules(lists:nthtail(1, Address), N - 1, Rules, Rules);

check_name_rules(Address, N, [Head|Tail], Rules) ->
	AddressPattern = [$=,$.] ++ string:join(Address,"."),
	case Head of
		#rule{address = AddressPattern} ->
			Head;
		_ ->
		check_name_rules(Address, N, Tail, Rules)
	end.

check_empty_rules(Rules) ->
	check_full_rules("", Rules).

watcher(RulesFile, SleepTime, Rules) ->
	Watcher = self(),
	spawn(fun() -> recheck_alarm(SleepTime, Watcher) end),
	Mtime = check_file_ts(RulesFile),
	watcher(RulesFile, SleepTime, Rules, Mtime).

watcher(RulesFile, SleepTime, Rules, Mtime) ->
	receive
		{new_rules, Peer, TS} ->
			if
				TS < Mtime ->
					Peer ! {new_rules, Mtime, Rules};
				true ->
					Peer ! no_new_rules
			end,
			watcher(RulesFile, SleepTime, Rules, Mtime);
		recheck ->
			Watcher = self(),
			spawn(fun() -> recheck_alarm(SleepTime, Watcher) end),
			NewMtime = check_file_ts(RulesFile, Mtime),
			if
				NewMtime > Mtime ->
					case parse_file(RulesFile) of
						error ->
							NewRules = Rules;
						NewRules ->
							ok
					end;
				true ->
					NewRules = Rules
			end,
			watcher(RulesFile, SleepTime, NewRules, NewMtime)
	end.

recheck_alarm(SleepTime, Watcher) ->
	sleep(SleepTime),
	Watcher ! recheck.

check_file_ts(RulesFile) ->
	check_file_ts(RulesFile, 0).

check_file_ts(RulesFile, Mtime) ->
	case file:read_file_info(RulesFile) of
		{ok, F} ->
			calendar:datetime_to_gregorian_seconds(F#file_info.mtime);
		_ ->
			Mtime
	end.
