%%%-------------------------------------------------------------------
%%% @author Stephen Gibberd <stephen.gibberd@2600hz.com>
%%% Created :  3 Jul 2013 by Stephen Gibberd <stephen.gibberd@2600hz.com>
%%%-------------------------------------------------------------------
-module(radius).

%% API
-export([start/0]).


start() ->
    application:set_env(eradius, client_ports , 2),
    application:set_env(eradius, client_ip , "0.0.0.0"),
    eradius_client:start_link(),
    application:set_env(eradius_dict, tables , 
                        [dictionary,dictionary_freeradius]),
    eradius_dict:start_link(),
    catch crypto:start(),
    application:start(radius).
    

    
