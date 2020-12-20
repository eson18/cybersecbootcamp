#!/bin/bash

#Shell script to analyze employee schedules
#First arg is date MMDD, second arg is time
cat $1_Dealer_schedule | awk -F" " '{print $1, $2, $5, $6}' | grep "$2"
