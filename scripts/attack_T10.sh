#!/bin/bash

## useful vars
jar_name=bcprov-jdk15on-158.jar
thePath="cs1653-2017fa-jbd29-mar257-zds14"
myTerm="terminator"
ct=30;

clientCmd="java -cp .:$jar_name RunClientApp"

if [[ $# > 1 ]]; then
  #statements
  ct=$1;
fi


cd src/
cd ../src/
echo "I'm in $PWD"
if [[ $PWD != *"$thePath"* ]]; then
  echo "In the wrong directory! Make sure the /src folder is in this directory."
  exit
fi

cp "../scripts/attInput" "../scripts/T10_input"
echo "aaaaaaaa" >> "../scripts/T10_input"
attIn="../scripts/T10_input"


for (( i = 0; i < ct ; i++ )); do
  #statements
  $clientCmd < $attIn &
done
