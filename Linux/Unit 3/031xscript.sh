#!/bin/bash

#Shell script to analyze Dealer schedule files and match with findings from Player_Analysis
#$1 is filename

cat $1 | awk -F" " '{print $1, $2, $5, $6}' | grep "02:00:00 PM" >> Dealers_working_during_losses

echo DONE

