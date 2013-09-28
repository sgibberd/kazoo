cd `dirname $0`

erl -pa ebin -pa ../../core/*/ebin -pa ../../deps/*/ebin -pa ../jonny5/ebin -sname radius -s radius
