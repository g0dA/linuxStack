#!./bash
function _stop {
	sleep 8
	exit
}
trap _stop INT TERM QUIT

while : ;do
	sleep 1
done
