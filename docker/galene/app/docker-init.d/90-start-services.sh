#!/bin/sh

echo "[+] Starting galene ..."

cd ${GALENE_PATH}

echo "  - exec ${GALENE_PATH}/galene\
${GALENE_CPUPROFILE:+ -cpuprofile ${GALENE_CPUPROFILE}}\
${GALENE_DATA:+ -data ${GALENE_DATA}}\
${GALENE_GROUPS:+ -groups ${GALENE_GROUPS}}\
${GALENE_HTTP:+ -http ${GALENE_HTTP}}\
${GALENE_INSECURE:+ -insecure}\
${GALENE_MDNS:+ -mdns}\
${GALENE_MEMPROFILE:+ -memprofile ${GALENE_MEMPROFILE}}\
${GALENE_MUTEXPROFILE:+ -mutexprofile ${GALENE_MUTEXPROFILE}}\
${GALENE_RECORDINGS:+ -recordings ${GALENE_RECORDINGS}}\
${GALENE_REDIRECT:+ -redirect ${GALENE_REDIRECT}}\
${GALENE_RELAY_ONLY:+ -relay-only}\
${GALENE_STATIC:+ -static ${GALENE_STATIC}}\
${GALENE_TURN+ -turn ${GALENE_TURN:-''}}"

exec ./galene \
      ${GALENE_CPUPROFILE:+-cpuprofile ${GALENE_CPUPROFILE}} \
      ${GALENE_DATA:+-data ${GALENE_DATA}} \
      ${GALENE_GROUPS:+-groups ${GALENE_GROUPS}} \
      ${GALENE_HTTP:+-http ${GALENE_HTTP}} \
      ${GALENE_INSECURE:+-insecure} \
      ${GALENE_MDNS:+-mdns} \
      ${GALENE_MEMPROFILE:+-memprofile ${GALENE_MEMPROFILE}} \
      ${GALENE_MUTEXPROFILE:+-mutexprofile ${GALENE_MUTEXPROFILE}} \
      ${GALENE_RECORDINGS:+-recordings ${GALENE_RECORDINGS}} \
      ${GALENE_REDIRECT:+-redirect ${GALENE_REDIRECT}} \
      ${GALENE_RELAY_ONLY:+-relay-only} \
      ${GALENE_STATIC:+-static ${GALENE_STATIC}} \
      ${GALENE_TURN+-turn ${GALENE_TURN:-''}}
