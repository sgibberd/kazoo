%%%-------------------------------------------------------------------
%%% @author Stephen Gibberd <stephen.gibberd@2600hz.com>
%%% Created :  9 Aug 2013 by Stephen Gibberd <stephen.gibberd@2600hz.com>
%%%-------------------------------------------------------------------
-module(radius_handler).

-include("radius.hrl").

%% API
-export([handle_req/2
	 ,handle_event/2
	 ,authz_req/2
	 ,reauthz_req/2
	 ,identify_req/2
	 ,cdr/2
	 ]).

handle_req(JObj,_Props) ->
    error_logger:info_msg("request ~p~n",[JObj]).

handle_event(JObj,_Props) ->
    error_logger:info_msg("event ~p~n",[JObj]).

authz_req(JObj, Props) ->
    error_logger:info_msg("authz_req~n~p~n",[JObj]),
    Result = case authorize(JObj) of
		 ok ->
		     {'ok', 'limits_disabled'};
		 Reason ->
		     {'error',Reason}
	     end,
    send_resp(JObj
	      ,props:get_value('queue', Props)
	      ,limits
	      ,Result
	     ).
reauthz_req(JObj, Props) ->
    error_logger:info_msg("reauthz_req ~p ~p~n",[JObj,Props]),
    case authorize(JObj) of 
	ok ->
	    send_allow_resp(JObj);
	_ ->
	    send_deny_resp(JObj)
    end.

identify_req(JObj, _Props) ->
    error_logger:info_msg("identify_req ~p~n",[JObj]),
    j5_authz_identify:handle_req(JObj, _Props).


cdr(JObj, _Props) ->
%    error_logger:info_msg("got CDR ~p~n",[JObj]),
    bill_cdr(JObj
	     ,wh_json:get_integer_value(<<"Billing-Seconds">>,JObj)
	     ,wh_json:get_value(<<"Call-Direction">>,JObj) 
	     ,wh_json:get_value(<<"Other-Leg-Call-ID">>,JObj)
	    ),
    ok.

%%% Private functions

authorize(JObj) ->
    Account = wh_json:get_value(<<"Auth-Account-ID">>, JObj),
    AccountId = wh_util:format_account_id(Account, 'raw'),
    AccountDb = wh_util:format_account_id(Account, 'encoded'),
    case couch_mgr:open_cache_doc(AccountDb, AccountId) of
	{ok,Acc} ->
	    User = wh_json:get_string_value(<<"realm">>,Acc),
	    Password = wh_util:to_list(AccountId),
	    error_logger:info_msg("sending ~p ~p ~p~n~p~n",[User,Password,get_nas_address(),get_radius_server()]),
	    case eradius_client:send_auth_request(User
						  ,Password
						  ,get_nas_address()
						  ,get_radius_server()
						 ) of
		accept ->
		    ok;
		reject ->
		    "no credit";
		_ ->
		    "timeout"
	    end;
	_ ->
	    "no account"
    end.

bill_cdr(_,0,_,_) ->
    dont_bill;
bill_cdr(_,_,_,'undefined') ->
    dont_bill;
bill_cdr(JObj,SessionTime,<<"inbound">>,OtherLeg) ->
    Customer = wh_json:get_value(<<"Custom-Channel-Vars">>,JObj),
    case wh_json:get_value(<<"Inception">>,Customer) of
	<<"off-net">> ->
	    no_bill;
	<<"on-net">> ->
	    CallId = wh_json:get_value(<<"Call-ID">>,JObj),
	    SessionId = wh_util:to_list(<<CallId:8/binary>>), 
	    CallingStation = wh_json:get_string_value(<<"From-Uri">>,JObj),
	    User = wh_json:get_string_value(<<"Realm">>,Customer),
	    case wh_cache:peek_local(?RADIUS_CACHE,OtherLeg) of
		{ok, CalledStation} ->
		    error_logger:info_msg("acc: ~p ~p ~p ~p~n",[User,CalledStation,CallingStation,SessionTime]),
		    spawn(fun() -> 
				  eradius_client:send_acc_request(
				    CalledStation
				    ,CallingStation
				    ,SessionId
				    ,User
				    ,SessionTime
				    ,get_nas_address()
				    ,get_radius_server())
			  end);
		_ ->
		    wh_cache:store_local(?RADIUS_CACHE
					 ,CallId
					 ,{CallingStation,User}
					 ,[{'expires',60}])
	    end
    end;
bill_cdr(JObj,SessionTime,<<"outbound">>,OtherLeg) ->
    CalledStation = wh_json:get_string_value(<<"To-Uri">>,JObj),
    CallId = wh_json:get_value(<<"Call-ID">>,JObj),
    case wh_cache:peek_local(?RADIUS_CACHE,OtherLeg) of
	{ok, {CallingStation,User}} ->
	    SessionId = wh_util:to_list(<<CallId:8/binary>>),
	    spawn(fun() ->
			  eradius_client:send_acc_request(CalledStation
							  ,CallingStation
							  ,SessionId
							  ,User
							  ,SessionTime
							  ,get_nas_address()
							  ,get_radius_server())
		  end),
	    ok;
	_ ->
	    wh_cache:store_local(?RADIUS_CACHE
				 ,CallId
				 ,CalledStation
				 ,[{'expires',60}])
    end.

get_nas_address() ->
    case wh_cache:peek_local(?RADIUS_CACHE,<<"nasaddress">>) of
	{ok,Val} ->
	    Val;
	_ ->
	    {ok,IPs} = inet:getif(),
	    MyIp = hd([IP || {IP,_,_} <- IPs, IP =/= {127,0,0,1} ]),
	    wh_cache:store_local(?RADIUS_CACHE,<<"nasaddress">>,MyIp),
	    MyIp
    end.
		  
get_radius_server() ->
    case wh_cache:peek_local(?RADIUS_CACHE,<<"serverlist">>) of
	{ok,Val} ->
	    Val;
	_ ->
	    {ok,RS} = couch_mgr:open_cache_doc(<<"system_config">>
						   ,<<"radius">>),
	    S2 = [ 
		   {list_to_ip(wh_json:get_value(<<"ip">>,S))
		    ,wh_json:get_integer_value(<<"port">>,S,1812)
		    ,wh_json:get_string_value(<<"secret">>,S)
		   }
		   || S <- wh_json:get_value(<<"server">>,RS)],
	    wh_cache:store_local(?RADIUS_CACHE,<<"serverlist">>,S2),
	    S2
    end.
		       
list_to_ip(IP) ->
    list_to_tuple([wh_util:to_integer(Part) || Part <- re:split(IP,"[.]")]).
    
send_allow_resp(JObj) ->
    send_allow_resp(JObj, undefined).

send_allow_resp(JObj, CCVs) ->
    send_resp(JObj, CCVs, <<"true">>).

-spec send_deny_resp(wh_json:json_object()) -> 'ok'.
-spec send_deny_resp(wh_json:json_object(), wh_json:json_object()) -> 'ok'.

send_deny_resp(JObj) ->
    send_deny_resp(JObj, undefined).

send_deny_resp(JObj, CCVs) ->
    error_logger:info_msg("reauthorization failed", []),
    send_resp(JObj, CCVs, <<"false">>).


-spec send_resp(wh_json:json_object(),  ne_binary(), #limits{}, {'ok', 'credit' | 'flatrate'} | {'error', _}) -> 'ok'.

send_resp(JObj, Q, _Limits, {'error', Reason}) ->
    Resp = [{<<"Is-Authorized">>, <<"false">>}
            ,{<<"Type">>, wh_util:to_binary(Reason)}
            ,{<<"Msg-ID">>, wh_json:get_value(<<"Msg-ID">>, JObj)}
            ,{<<"Call-ID">>, wh_json:get_value(<<"Call-ID">>, JObj)}
            | wh_api:default_headers(Q, ?APP_NAME, ?APP_VERSION)
           ],
    wapi_authz:publish_authz_resp(wh_json:get_value(<<"Server-ID">>, JObj), Resp);
send_resp(JObj, Q, _, {'ok', Type}) ->
    Resp = [{<<"Is-Authorized">>, <<"true">>}
            ,{<<"Type">>, wh_util:to_binary(Type)}
            ,{<<"Msg-ID">>, wh_json:get_value(<<"Msg-ID">>, JObj)}
            ,{<<"Call-ID">>, wh_json:get_value(<<"Call-ID">>, JObj)}
            | wh_api:default_headers(Q, ?APP_NAME, ?APP_VERSION)
           ],
    wapi_authz:publish_authz_resp(wh_json:get_value(<<"Server-ID">>, JObj), Resp).
-spec send_resp(wh_json:json_object(), wh_json:json_object(), ne_binary()) -> 'ok'.
send_resp(JObj, CCVs, Authd) when Authd == <<"true">> 
				  orelse Authd == <<"false">> ->
    Resp = [{<<"Is-Authorized">>, Authd}
            ,{<<"Type">>, wh_json:get_value(<<"Type">>, JObj)}
            ,{<<"Msg-ID">>, wh_json:get_value(<<"Msg-ID">>, JObj)}
            ,{<<"Call-ID">>, wh_json:get_value(<<"Call-ID">>, JObj)}
            ,{<<"Custom-Channel-Vars">>, CCVs}
            | wh_api:default_headers(<<>>, ?APP_NAME, ?APP_VERSION)
           ],
    wapi_authz:publish_reauthz_resp(wh_json:get_value(<<"Server-ID">>, JObj)
                                    ,props:filter_undefined(Resp)).



