#!/bin/bash

function _exit {
	echo "exit with trap"
}

trap _exit INT TERM QUIT

sleep 25 
echo "123"
