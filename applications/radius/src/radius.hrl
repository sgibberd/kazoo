-ifndef(RADIUS_HRL).

-include_lib("whistle/include/wh_amqp.hrl").
-include_lib("whistle/include/wh_types.hrl").
-include_lib("whistle/include/wh_log.hrl").
-include_lib("whistle/include/wh_databases.hrl").

-define(RADIUS_CACHE, radius_cache).

-define(APP_VERSION, <<"1.0.0">>).
-define(APP_NAME, <<"radius">>).

-record(limits, {account_id = undefined
                 ,account_db = undefined
                 ,enabled = true
                 ,twoway_trunks = -1
                 ,inbound_trunks = 0
                 ,resource_consuming_calls = -1
                 ,calls = -1
                 ,allow_prepay = true
                 ,allow_postpay = false
                 ,max_postpay_amount = 0
                 ,reserve_amount = 0
                 ,allotments = wh_json:new()
                 ,soft_limit_inbound = false
                 ,soft_limit_outbound = false
                }).
-type radius_limits() :: #limits{}.

-define(RADIUS_HRL, true).
-endif.
