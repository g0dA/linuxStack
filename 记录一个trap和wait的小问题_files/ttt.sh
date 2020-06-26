#!./bash

pid=
function handle_exit {
	sleep 10
	if [ x"${pid}" != x ]
	then
		echo "kill -15 ${pid}"
		kill -15 ${pid}
	fi
}
trap handle_exit INT TERM QUIT

./aaa.sh 

pid=$!
wait ${pid} 
exit_code=$?
echo "exit with code ${exit_code}"
exit ${exit_code}
