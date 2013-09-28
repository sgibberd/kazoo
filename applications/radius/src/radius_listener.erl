-module(radius_listener).
-behaviour(gen_listener).

%% API
-export([start_link/0,start/0,init/1,handle_call/3,handle_cast/2,handle_info/2
         ,terminate/2,code_change/3]).

-record(state,{}).

-define(SERVER,?MODULE).
-define(RESPONDERS, [{{radius_handler,authz_req},
		      [{<<"authz">>, <<"authz_req">>}]}
		     ,{{radius_handler,reauthz_req},
		       [{<<"authz">>, <<"reauthz_req">>}]}
		     ,{{radius_handler,identify_req},
		       [{<<"authz">>, <<"identify_req">>}]}
		     ,{{radius_handler,cdr},
		       [{<<"call_detail">>, <<"cdr">>}]}
		    ]).
		       
		     
-define(BINDINGS, [{call, [{restrict_to, [cdr]}, {callid, <<"*">>}]}
                   ,{authz, []}
                   ,{self, []}
                  ]).
-define(QUEUE_NAME, <<"radius_listener">>).
%-define(QUEUE_OPTIONS, [{exclusive, false}]).
%-define(CONSUME_OPTIONS, [{exclusive, false}]).


start() ->
    application:start(radius).

start_link() ->
    error_logger:info_msg("starting new stats proc"),
    [wh_util:ensure_started(A) || A <- [ sasl
					 ,whistle_amqp
					 ,whistle_couch
					 ,ibrowse
					 ,lager
				       ] ],
    gen_listener:start_link(?MODULE
                            ,[{bindings, ?BINDINGS}
                              ,{responders, ?RESPONDERS}
                              ,{queue_name, ?QUEUE_NAME}
                              %,{queue_options, ?QUEUE_OPTIONS}
                              %,{consume_options, ?CONSUME_OPTIONS}
                             ]
                            ,[]).

init([]) ->
    {ok,#state{}}.

handle_call(_Request,_From,State) ->
    {reply,{error,not_implemented},State}.

handle_cast(_Request,State) ->
    {noreply,State}.

handle_info(_Request,State) ->
    {noreply,State}.

code_change(_OldVsn, State, _Extra) ->
    {'ok', State}.

terminate(_Reason, _State) ->
    error_logger:info_msg("listener terminating: ~p", [_Reason]).
