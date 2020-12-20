#!/bin/bash

#Shell script to analyze employee schedules for all games
#First arg is date MMDD, second arg is time, third arg is casino game

#Casino game not specified, show all dealers for all games
if [ -z "$3" ]
then cat $1_Dealer_schedule | awk -F" " '{print $1, $2, "BlackJack: "$3, $4, "Roulette: "$5, $6, "Texas_Hold_EM: "$7, $8}' | grep "$2"

else
#Blackjack selected
	if [ $3 = 1 ]
	then cat $1_Dealer_schedule | awk -F" " '{print $1, $2, "Blackjack: "$3, $4}' | grep "$2"

#Roulette selected
	elif [ $3 == 2 ]
	then cat $1_Dealer_schedule | awk -F" " '{print $1, $2, "Roulette: "$5, $6}' | grep "$2"

#Texas_Hold_EM selected
	elif [ $3 == 3 ]
	then cat $1_Dealer_schedule | awk -F" " '{print $1, $2, "Texas_Hold_EM: "$7, $8}' | grep "$2"
	fi
fi

