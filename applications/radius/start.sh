cd `dirname $0`

erl -pa ebin -pa ../../deps/*/ebin -pa ../../core/*/ebin  -sname radius -s radius -detached
