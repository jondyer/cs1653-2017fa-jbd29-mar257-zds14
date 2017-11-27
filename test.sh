#!/bin/env bash
############################################################################################################
## The flag '-f' removes binaries for a fresh start.
## The flag '-t' runs the script with the file "ClientInput" as the input to the ClientApp. Each line in
##    that file is a command. Modify it as you see fit for unit-testing purposes (be sure to end
##    appropriately, i.e. quitting the app with a 'q', or else it will exit with an error). Running with
##     the '-t' flag also keeps the ClientApp terminal open so you can see the results.
## Run with the optional flag '-m' if you're on a Mac.
## If you don't use Terminator, change variable 'myTerm' to appropriate value (xterm, gnome-terminal, etc).
############################################################################################################

## useful vars
jar_name=bcprov-jdk15on-158.jar
thePath="cs1653-2017fa-jbd29-mar257-zds14"
clientIn="../ClientInput"
myTerm="terminator"
macTerm="open -a terminal ."
fresh="echo"
remove="rm *.bin"
sleep1="sleep 2s"
sleep2="sleep 2s"
sleep3="sleep 4s"
clientCmd="java -cp .:$jar_name RunClientApp"
keep="echo"
testing=""

while getopts ":fmt" opt; do
  case $opt in
    m)
      echo "Mac mode (or MAX mode) activated"
      myTerm=$macTerm
      ;;
    f)
      echo "Fresh start..."
      fresh=$remove
      sleep1="sleep 3s"
      sleep2="sleep 4s"
      sleep3="sleep 8s"
      ;;
    t)
      echo "Full client test..."
      testing="True"
      keep="bash"
      ;;
    \?)
      echo "Invalid option: -$OPTARG"
      ;;
  esac
done


## First check directory
cd ./src/
echo "I'm in $PWD"
if [[ $PWD != *"$thePath"* ]]; then
  echo "In the wrong directory! Make sure the /src folder is in this directory."
  exit
fi

## Remove binaries if flag is set
$fresh

## Compile everything
javac -cp .:$jar_name *.java

## Now start new terminals and run each part
run_Trent() {
  echo "Starting TrentServer..."
  pwd
  java -cp .:$jar_name RunTrentServer
}

run_GS() {
  echo "Starting GroupServer..."
  local GSin="../GSinput"
  pwd
  echo "Sleeping..."
  java -cp .:$jar_name RunGroupServer < $GSin
}

run_FS() {
  echo "Starting FileServer..."
  pwd
  echo "Sleeping..."
  java -cp .:$jar_name RunFileServer
}

run_Client() {
  echo "Starting ClientApp..."
  pwd
  echo "Sleeping..."
  if [[ $testing =~ "True" ]]; then
    $clientCmd < $clientIn
  elif [ -z "$testing" ]; then
    $clientCmd
  fi
}


## Export vars and functions
export jar_name
export testing
export clientIn
export clientCmd
export sleep1
export sleep2
export sleep3
export -f run_Trent
export -f run_GS
export -f run_FS
export -f run_Client

$myTerm -x bash -c "run_Trent" & $sleep1
$myTerm -x bash -c "run_GS" & $sleep2
$myTerm -x bash -c "run_FS" & $sleep3
$myTerm -x bash -c "run_Client; $keep"
