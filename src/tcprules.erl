-module(tcprules).
-export([parse_file/1, check_full_rules/2, check_network_rules/3, check_name_rules/3]).

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
%			io:format("Acc: ~p~n", [Acc]),
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
%			io:format("Parsing line ~p:~p~n", [Count, Line]),
			case re:run(Line, "^(.*):(allow|deny)([^#]*)[#|\n].*") of
				{match, Match} ->
%					io:format("Rule: ~p~n", [Match]),
					[_|Boundaries] = Match,
					Fields = lists:map( fun(X) ->
						{Start, Length} = X,
						string:substr(Line, Start + 1, Length)
					end, Boundaries),
					[Address, Type, Environment] = Fields,
					Acc ++ [{rule, list_to_atom(Type), Address, string:tokens(string:strip(Environment), ",")}];
				_ ->
					io:format("Unknown rule in Line ~p: ~p~n", [Count, Line]),
					Acc
			end
	end.


check_full_rules(undefined, _) ->
	not_found;

check_full_rules(Address, []) ->
	not_found;

check_full_rules(Address, [Head|Tail]) ->
%	io:format("check_host_rules called for ~p~n", [Head]),
	case Head of
		{rule, Result, Address, _} ->
			Head;
		_ ->
		check_full_rules(Address, Tail)
	end.

check_network_rules(undefined, _, _) ->
	not_found;

check_network_rules(Address, N, Rules) ->
	check_network_rules(Address, N, Rules, Rules).

check_network_rules(Address, N, [], Rules) when N =< 1 ->
	not_found;

check_network_rules(Address, N, [], Rules) ->
	io:format("check_network_rules called for ~p(~p)~n", [Address, N]),
	check_network_rules(lists:sublist(Address, N - 1), N - 1, Rules, Rules);

check_network_rules(Address, N, [Head|Tail], Rules) ->
	io:format("check_network_rules called for ~p(~p)~n", [Address, N]),
	AddressPattern = string:join(Address,".") ++ [$.],
	io:format("~p~n", [AddressPattern]),
	case Head of
		{rule, Result, AddressPattern, _} ->
			Head;
		_ ->
		check_network_rules(Address, N, Tail, Rules)
	end.

check_name_rules(undefined, _, _) ->
	not_found;

check_name_rules(Address, N, Rules) ->
	check_name_rules(Address, N, Rules, Rules).

check_name_rules(Address, N, [], Rules) when N =< 1 ->
	not_found;

check_name_rules(Address, N, [], Rules) ->
	check_name_rules(lists:nthtail(1, Address), N - 1, Rules, Rules);

check_name_rules(Address, N, [Head|Tail], Rules) ->
	io:format("check_name_rules called for ~p(~p)~n", [Address, N]),
	AddressPattern = [$=,$.] ++ string:join(Address,"."),
%	io:format("~p~n", [AddressPattern]),
	case Head of
		{rule, Result, AddressPattern, _} ->
			Head;
		_ ->
		check_name_rules(Address, N, Tail, Rules)
	end.

check_empty_rules() ->
	allow.
