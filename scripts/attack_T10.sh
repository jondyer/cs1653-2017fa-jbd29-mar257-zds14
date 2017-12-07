#!/bin/bash

## useful vars
jar_name=bcprov-jdk15on-158.jar
thePath="cs1653-2017fa-jbd29-mar257-zds14"
attIn="../scripts/attInput"
myTerm="terminator"

clientCmd="java -cp .:$jar_name RunClientApp"

cd src/
cd ../src/
echo "I'm in $PWD"
if [[ $PWD != *"$thePath"* ]]; then
  echo "In the wrong directory! Make sure the /src folder is in this directory."
  exit
fi


for (( i = 0; i < 10; i++ )); do
  #statements
  $clientCmd < $attIn &
done
