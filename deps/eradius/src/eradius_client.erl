%% @doc This module contains a RADIUS client that can be used to send authentication and accounting requests.
%%   A counter is kept for every NAS in order to determine the next request id and sender port
%%   for each outgoing request. The implementation naively assumes that you won't send requests to a
%%   distinct number of NASs over the lifetime of the VM, which is why the counters are not garbage-collected.
%%
%%   The client uses OS-assigned ports. The maximum number of open ports can be specified through the
%%   ``client_ports'' application environment variable, it defaults to ``20''. The number of ports should not
%%   be set too low. If ``N'' ports are opened, the maximum number of concurrent requests is ``N * 256''.
%%
%%   The IP address used to send requests is read <emph>once</emph> (at startup) from the ``client_ip''
%%   parameter. Changing it currently requires a restart. It can be given as a string or ip address tuple,
%%   or the atom ``undefined'' (the default), which uses whatever address the OS selects.
-module(eradius_client).
-export([start_link/0
	 ,send_request/2
	 ,send_request/3
	 ,send_remote_request/3
	 ,send_remote_request/4]).

-export([send_acc_request/7
	 ,send_auth_request/4
	]).

%% internal
-export([reconfigure/0
	 ,send_remote_request_loop/6]).
-export([init/1
	 ,handle_call/3
	 ,handle_cast/2
	 ,handle_info/2
	 ,terminate/2
	 ,code_change/3
	]).

-behaviour(gen_server).

-include("dictionary.hrl").

-include("eradius_lib.hrl").
-define(SERVER, ?MODULE).
-define(DEFAULT_RETRIES, 2).
-define(DEFAULT_TIMEOUT, 5000).
-define(RECONFIGURE_TIMEOUT, 15000).
-define(GOOD_CMD(Req), Req#radius_request.cmd == 'request' orelse Req#radius_request.cmd == 'accreq').

-type nas_address() :: {inet:ip_address(), eradius_server:port_number(), eradius_lib:secret()}.
-type options() :: [{retries, pos_integer()} | {timeout, timeout()}].

%% ------------------------------------------------------------------------------------------
%% -- API
% @private
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

% @equiv send_request(NAS, Request, [])
-spec send_request(nas_address(), #radius_request{}) -> {ok, binary()} | {error, 'timeout' | 'socket_down'}.
send_request(NAS, Request) ->
    send_request(NAS, Request, []).

% @doc Send a radius request to the given NAS.
%   If no answer is received within the specified timeout, the request will be sent again.

send_auth_request(User,Password,NasIpAddress
		  ,RadiusServers = [{{RIP1,RIP2,RIP3,RIP4},_,_}|_]) ->
    Realm = lists:flatten(io_lib:format("~w.~w.~w.~w",[RIP1,RIP2,RIP3,RIP4])),
    Method = "INVITE",
    URI = "sip:" ++ User ++ "@" ++ Realm,
    Nonce = "1234abcd",
    
    Request = eradius_lib:new_radius_request(),
    Ha1 = md5hex(User ++ ":" ++ Realm ++ ":" ++ Password),
    Ha2 = md5hex(Method ++ ":" ++ URI),
    Response = md5hex(Ha1 ++ ":" ++ Nonce ++ ":" ++ Ha2),

    Attr = [{?User_Name,User}
	    ,{?NAS_IP_Address,NasIpAddress}
            ,{?Digest_Realm,Realm}
	    ,{?Digest_Nonce,Nonce}
	    ,{?Digest_Method,Method}
	    ,{?Digest_URI,URI}
	    ,{?Digest_Algorithm,"MD5"}
	    ,{?Digest_User_Name,User}
	    ,{?Digest_Response,Response}
	   ],
    AuthReq = eradius_lib:set_attributes(Request,Attr),

    Fun = fun(Server = {_,_,Secret},Status) ->
		  case Status of 
		      timeout ->
			  case send_request(Server,AuthReq,[{retries,2}]) of
			      {ok,Packet} ->
%				  io:format("Res: ~p~n",
%					    [eradius_lib:decode_request(Packet,
%									Secret)%]),
				  case eradius_lib:decode_request(Packet,Secret) of
				      #radius_request{cmd=Cmd} ->
					  Cmd;
				      _Other ->
%					  io:format("Decode ~p~n",[_Other]),
					  timeout
				  end;
			      _Other ->
%				  io:format("Decode2 ~p~n",[_Other]),
				  timeout
			  end;
		      _ ->
			  Status
		  end
	  end,
    lists:foldl(Fun,timeout,RadiusServers).

send_acc_request(CalledStation,CallingStation,SessionId,UserName,SessionTime,
		 NasIpAddress,ServerList) ->
    Req = eradius_lib:new_acc_req(),
    Attr = [{?NAS_Port_Id,"12"}
            ,{?Called_Station_Id,CalledStation}
            ,{?Calling_Station_Id,CallingStation}
            ,{?NAS_Port_Type,0}
            ,{?Acct_Session_Id,SessionId}
            ,{?User_Name,UserName}
            ,{?NAS_IP_Address,NasIpAddress}
	   ],
    StartAttrib = [{?Acct_Status_Type,eradius_lib:acct_status(start)} | Attr],
    StartReq = eradius_lib:set_attributes(Req,StartAttrib),
    EndAttrib = [{?Acct_Status_Type,eradius_lib:acct_status(stop)}
		 ,{?Acct_Session_Time,SessionTime}
		 | Attr],
    EndReq = eradius_lib:set_attributes(Req,EndAttrib),
    try_acc_servers(ServerList,StartReq,EndReq).

try_acc_servers([],_,_) ->
    fail;
try_acc_servers([{{_,_,_,_}=IP,Port,Secret} | RestServer], StartReq,EndReq) ->
    Retries = if length(RestServer) > 0 ->
		      1;
		 true ->
		      3
	      end,
    Server = {IP, Port+1,Secret},
    S = case send_request(Server,StartReq,[{retries,Retries}]) of
	    {ok,Packet} ->
		case eradius_lib:decode_request(Packet,Secret) of
		    #radius_request{cmd=accresp} ->
			send_request(Server,EndReq, [{retries,3}]),
			ok;
		    _ ->
			timeout
		end;
	    _ ->
		timeout
	end,
    if S == ok ->
	    ok;
       true ->
	    try_acc_servers(RestServer,StartReq,EndReq)
    end.
		    
-spec send_request(nas_address(), #radius_request{}, options()) -> {ok, binary()} | {error, 'timeout' | 'socket_down'}.
send_request({IP, Port, Secret}, Request, Options) when ?GOOD_CMD(Request) ->
    {Socket, ReqId} = gen_server:call(?SERVER, {wanna_send, {IP, Port}}),
    EncRequest = encode_request(Request#radius_request{reqid = ReqId, secret = Secret}),
    send_request_loop(Socket, ReqId, {IP, Port}, EncRequest, Options);
send_request(_NAS, _Request, _Options) ->
    error(badarg).

% @equiv send_remote_request(Node, NAS, Request, [])
-spec send_remote_request(node(), nas_address(), #radius_request{}) -> {ok, binary()} | {error, 'timeout' | 'node_down' | 'socket_down'}.
send_remote_request(Node, NAS, Request) ->
    send_remote_request(Node, NAS, Request, []).

% @doc Send a radius request to the given NAS through a socket on the specified node.
%   If no answer is received within the specified timeout, the request will be sent again.
%   The request will not be sent again if the remote node is unreachable.
-spec send_remote_request(node(), nas_address(), #radius_request{}, options()) -> {ok, binary()} | {error, 'timeout' | 'node_down' | 'socket_down'}.
send_remote_request(Node, {IP, Port, Secret}, Request, Options) when ?GOOD_CMD(Request) ->
    try gen_server:call({?SERVER, Node}, {wanna_send, {IP, Port}}) of
        {Socket, ReqId} ->
            EncRequest = encode_request(Request#radius_request{reqid = ReqId, secret = Secret}),
            SenderPid = spawn(Node, ?MODULE, send_remote_request_loop, [self(), Socket, ReqId, {IP, Port}, EncRequest, Options]),
            SenderMonitor = monitor(process, SenderPid),
            receive
                {SenderPid, Result} ->
                    erlang:demonitor(SenderMonitor, [flush]),
                    Result;
                {'DOWN', SenderMonitor, process, SenderPid, _Reason} ->
                    {error, socket_down}
            end
    catch
        exit:{{nodedown, Node}, _} ->
            {error, node_down}
    end;
send_remote_request(_Node, _NAS, _Request, _Options) ->
    error(badarg).

encode_request(Req = #radius_request{cmd = request}) ->
    eradius_lib:encode_request(Req#radius_request{authenticator = eradius_lib:random_authenticator()});
encode_request(Req = #radius_request{cmd = accreq}) ->
    eradius_lib:encode_reply_request(Req#radius_request{authenticator = eradius_lib:zero_authenticator()}).

						% @private
send_remote_request_loop(ReplyPid, Socket, ReqId, Peer, EncRequest, Options) ->
    ReplyPid ! {self(), send_request_loop(Socket, ReqId, Peer, EncRequest, Options)}.

send_request_loop(Socket, ReqId, Peer, EncRequest, Options) ->
    Retries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
    Timeout = proplists:get_value(timeout, Options, ?DEFAULT_TIMEOUT),
    SMon = erlang:monitor(process, Socket),
    send_request_loop(Socket, SMon, Peer, ReqId, EncRequest, Timeout, Retries).

send_request_loop(_Socket, SMon, _Peer, _ReqId, _EncRequest, _Timeout, 0) ->
    erlang:demonitor(SMon, [flush]),
    {error, timeout};
send_request_loop(Socket, SMon, Peer, ReqId, EncRequest, Timeout, RetryN) ->
%    io:format("Sent to ~p from ~p ReqId ~p~n",[Socket,self(),ReqId]),
    Socket ! {self(), send_request, Peer, ReqId, EncRequest},
    receive
        {Socket, response, ReqId, Response} ->
%	    io:format("Got response~n"),
            {ok, Response};
        {'DOWN', SMon, process, Socket, _} ->
            {error, socket_down}
    after
        Timeout ->
            send_request_loop(Socket, SMon, Peer, ReqId, EncRequest, Timeout, RetryN - 1)
    end.

%% @private
reconfigure() ->
    catch gen_server:call(?SERVER, reconfigure, ?RECONFIGURE_TIMEOUT).

%% ------------------------------------------------------------------------------------------
%% -- socket process manager
-record(state, {
    socket_ip :: inet:ip_address(),
    no_ports = 1 :: pos_integer(),
    idcounters = dict:new() :: dict(),
    sockets = array:new() :: array(),
    sup :: pid()
}).

%% @private
init([]) ->
    {ok, Sup} = eradius_client_sup:start(),
    case configure(#state{socket_ip = null, sup = Sup}) of
        {error, Error}  -> {stop, Error};
        Else            -> Else
    end.

%% @private
handle_call({wanna_send, Peer}, _From, State) ->
    {PortIdx, ReqId, NewIdCounters} = next_port_and_req_id(Peer, State#state.no_ports, State#state.idcounters),
    {SocketProcess, NewSockets} = find_socket_process(PortIdx, State#state.sockets, State#state.socket_ip, State#state.sup),
    NewState = State#state{idcounters = NewIdCounters, sockets = NewSockets},
    {reply, {SocketProcess, ReqId}, NewState};

%% @private
handle_call(reconfigure, _From, State) ->
    case configure(State) of
        {error, Error}  -> {reply, Error, State};
        {ok, NState}    -> {reply, ok, NState}
    end;

%% @private
handle_call(debug, _From, State) ->
    {reply, {ok, State}, State};

%% @private
handle_call(_OtherCall, _From, State) ->
    {noreply, State}.

%% @private
handle_cast(_Msg, State) -> {noreply, State}.

%% @private
handle_info({PortIdx, Pid}, State = #state{sockets = Sockets}) ->
    NSockets = update_socket_process(PortIdx, Sockets, Pid),
    {noreply, State#state{sockets = NSockets}};

handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, _State) -> ok.

%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

configure(State) ->
    {ok, ClientPortCount} = application:get_env(eradius, client_ports),
    {ok, ClientIP} = application:get_env(eradius, client_ip),
    case parse_ip(ClientIP) of
        {ok, Address} ->
            configure_address(State, ClientPortCount, Address);
        {error, _} ->
            eradius:error_report("Invalid RADIUS client IP: ~p~n", [ClientIP]),
            {error, {bad_client_ip, ClientIP}}
    end.

configure_address(State = #state{socket_ip = OAdd, sockets = Sockts}, NPorts, NAdd) ->
    case OAdd of
        null    ->
            {ok, State#state{socket_ip = NAdd, no_ports = NPorts}};
        NAdd    ->
            configure_ports(State, NPorts);
        _       ->
            eradius:info_report("Reopening RADIUS client sockets (client_ip changed)~n", []),
            array:map(  fun(_PortIdx, Pid) ->
                                case Pid of
                                    undefined   -> done;
                                    _           -> Pid ! close
                                end
                         end, Sockts),
            {ok, State#state{sockets = array:new(), socket_ip = NAdd, no_ports = NPorts}}
    end.

configure_ports(State = #state{no_ports = OPorts, sockets = Sockets}, NPorts) ->
    if
        OPorts =< NPorts ->
            {ok, State#state{no_ports = NPorts}};
        true ->
            Counters = fix_counters(NPorts, State#state.idcounters),
            NSockets = close_sockets(NPorts, Sockets),
            {ok, State#state{sockets = NSockets, no_ports = NPorts, idcounters = Counters}}
    end.

fix_counters(NPorts, Counters) ->
    dict:map(   fun(_Peer, Value = {NextPortIdx, NextReqId}) ->
                        case NextPortIdx >= NPorts of
                            false   -> Value;
                            true    -> {0, NextReqId}
                        end
                end, Counters).

close_sockets(NPorts, Sockets) ->
    case array:size(Sockets) =< NPorts of
        true    ->
            Sockets;
        false   ->
            List = array:to_list(Sockets),
            {_, Rest} = lists:split(NPorts, List),
            lists:map(  fun(Pid) ->
                                case Pid of
                                    undefined   -> done;
                                    _           -> Pid ! close
                                end
                        end, Rest),
            array:resize(NPorts, Sockets)
    end.

next_port_and_req_id(Peer, NumberOfPorts, Counters) ->
    case dict:find(Peer, Counters) of
        {ok, {NextPortIdx, ReqId}} when ReqId < 255 ->
            NextReqId = (ReqId + 1);
        {ok, {PortIdx, 255}} ->
            NextPortIdx = (PortIdx + 1) rem (NumberOfPorts - 1),
            NextReqId = 0;
        error ->
            NextPortIdx = erlang:phash2(Peer, NumberOfPorts),
            NextReqId = 0
    end,
    NewCounters = dict:store(Peer, {NextPortIdx, NextReqId}, Counters),
    {NextPortIdx, NextReqId, NewCounters}.

find_socket_process(PortIdx, Sockets, SocketIP, Sup) ->
    case array:get(PortIdx, Sockets) of
        undefined ->
            Res = supervisor:start_child(Sup, {PortIdx,
                {eradius_client_socket, start, [SocketIP, self(), PortIdx]},
                transient, brutal_kill, worker, [eradius_client_socket]}),
            Pid = case Res of
                {ok, P} -> P;
                {error, already_present} ->
                    {ok, P} = supervisor:restart_child(Sup, PortIdx),
                    P
            end,
            {Pid, array:set(PortIdx, Pid, Sockets)};
        Pid when is_pid(Pid) ->
            {Pid, Sockets}
    end.

update_socket_process(PortIdx, Sockets, Pid) ->
    array:set(PortIdx, Pid, Sockets).

md5hex(Str) ->
    MD5 = erlang:md5(Str),
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= MD5]).

parse_ip(undefined) ->
    {ok, undefined};
parse_ip(Address) when is_list(Address) ->
    inet_parse:address(Address);
parse_ip(T = {_, _, _, _}) ->
    {ok, T};
parse_ip(T = {_, _, _, _, _, _}) ->
    {ok, T}.
