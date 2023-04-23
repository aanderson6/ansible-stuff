#!/bin/bash

tempuser=$1

IFS=:
read var1 hashed var3 <<< `sudo getent shadow | grep "^$tempuser"`

echo $hashed
