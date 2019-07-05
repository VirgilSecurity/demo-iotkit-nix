#!/bin/bash
#***************************************************************************************

TIMEOUT=15
WHILE_SLEEP=1

#***************************************************************************************
# Check run in openwrt
if [ -f /etc/openwrt_release ]; then
 echo "### Tests running in Openwrt ###"
 OPENWRT=1
else
 OPENWRT=0
fi

#***************************************************************************************
SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
count=0
RUNS_FAILED=0
RUNS_SUCCESS=0
TERM_ON_ERR=0
# export LSAN_OPTIONS=verbosity=1:log_threads=1
#***************************************************************************************
if [[ $1 -gt 0 ]]; then
   FOR_COUNT=$1
else
   FOR_COUNT=1
fi

#***************************************************************************************
TEST_EXEC="cmake-build-jenkins/tests/rpi_gw_tests"

#*************************************************************************************
change_retcode() {
 return $1
}

#***************************************************************************************
check_error() {
   RETRIES=$?
   if [ $RETRIES != 0 ]; then
        echo "----------------------------------------------------------------------"
        echo "####### !!! PROCESS ERROR ERRORCODE=[$RETRIES] WHILE:($count of $FOR_COUNT) ########"
        echo "----------------------------------------------------------------------"
        [ "$1" == "0" ] || exit $RETRIES
   else
        echo "-----# Process OK. ---------------------------------------------------"
   fi
   return $RETRIES
}

#***************************************************************************************
run_valgrind() {
   valgrind --error-exitcode=128 --tool=memcheck --leak-check=full \
                  --leak-resolution=med --track-origins=yes --vgdb=no $@
   return $?
}

#***************************************************************************************
# Check run in valgrind
if [ "$RUN_IN_VALGRIND" == "true" ]; then
 TEST_EXEC="run_valgrind $TEST_EXEC"
fi

#***************************************************************************************
err_counter() {
   if [ "$?" -gt "0" ]; then
      let RUNS_FAILED++
   else
      let RUNS_SUCCESS++
   fi
}

parse_err() {
 cat temp.log | grep "TEST ERROR" > /dev/null 2>&1
 if [ $? == 0 ]; then
   return 1
 else
   return 0
 fi
}
#***************************************************************************************
cd "${SCRIPT_FOLDER}/../../"

for (( count=1; (count<=FOR_COUNT); count++ ))
do
   echo "----------------------------------------------------------------------"
   echo "##### BEGIN rpi_gw_tests TESTS WHILE:($count of $FOR_COUNT) ##########"
   echo "----------------------------------------------------------------------"
   ${TEST_EXEC}
   check_error 0
   err_counter
   echo "----------------------------------------------------------------------"
   echo "############# FINISH USER SPACE TEST WHILE:($count of $FOR_COUNT) ########"
   echo "----------------------------------------------------------------------"
   sleep $WHILE_SLEEP
done

echo "----------------------------------------------------------------------"
echo "### SUMMARY: SUCCESS:[${RUNS_SUCCESS}] FAILED:[${RUNS_FAILED}] WHILES:[${FOR_COUNT}] ################"
echo "----------------------------------------------------------------------"

# Return errcode
if [[ $RUNS_FAILED -gt 0 ]]; then
  exit 1
else
  exit 0
fi
