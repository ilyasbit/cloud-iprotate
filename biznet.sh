#!/bin/bash

networkId=70229857-9658-416a-96cf-27f19cfa8606
projectId=1aec406913d34dfdbc64d3c2dc5c3314
portId=23e26cdf-9686-4d04-b23d-938eb28509cb
region=Jakarta-2
token=gAAAAABkkperZ1kyeDuEQak7OxcFnfI6otKF_6ELTvA3n_-Y1CkAQ2MR_yINEe3DxPi98woDRodYD2R3E4JnnIQdV14zimOuBZ_oV1aLiewHRb6FNavrgPUolLotA6yeX3PgaHg6PLkSSKYKvh63h9Cg6ZQHpn9Krr6NDOuUl44Pzga33Dm7iacpqxn30L96kE2ULxSFg_79mdmPjTqflDagPa_azjEaVHyY0D5zS8piSXElmRoDpp8

function getFloatingIp() {
  curl -s 'https://portal.biznetgio.com/api/openstack/floatingips' \
    -H 'Accept: application/json, text/plain, */*' \
    -H "Openstack-Region: ${region}" \
    -H "X-Auth-Token: ${token}" \
    --compressed
}

function deleteIp() {
  curl -s "https://portal.biznetgio.com/api/openstack/floatingips/${floatingIp}" \
    -X 'DELETE' \
    -H 'Accept: application/json, text/plain, */*' \
    -H "Openstack-Region: ${region}" \
    -H "X-Auth-Token: ${token}" \
    --compressed >/dev/null
}

function createIp() {
  curl -s 'https://portal.biznetgio.com/api/openstack/floatingips' \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'Content-Type: application/json;charset=UTF-8' \
    -H "Openstack-Region: ${region}" \
    -H "X-Auth-Token: ${token}" \
    --data-raw "{\"floatingip\":{\"project_id\":\"${projectId}\",\"floating_network_id\":\"${networkId}\"},\"description\":\"\"}" \
    --compressed
}

function attachIp() {
  curl -s "https://portal.biznetgio.com/api/openstack/floatingips/${floatingIp}" \
    -X 'PUT' \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'Accept-Language: en-US,en;q=0.9,id;q=0.8' \
    -H 'Application-Name: openstack' \
    -H 'Content-Type: application/json;charset=UTF-8' \
    -H "Openstack-Region: ${region}" \
    -H "X-Auth-Token: ${token}" \
    --data-raw "{\"floatingip\":{\"port_id\":\"${portId}\"}}" \
    --compressed >/dev/null
}

function getInstanceIp() {
  ipdetail=$(curl -s "https://portal.biznetgio.com/api/openstack/floatingips?port_id=${portId}" \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'Accept-Language: en-US,en;q=0.9,id;q=0.8' \
    -H "Openstack-Region: ${region}" \
    -H "X-Auth-Token: ${token}" \
    --compressed)
  ipaddress=$(echo $ipdetail | jq -r ".data[] | select(.port_id == \"${portId}\") | .floating_ip_address")
  if [[ ! $ipaddress ]]; then
    echo "{\"public_ip\": null}"
  else
    floatingIp=$(echo $ipdetail | jq -r ".data[] | select(.port_id == \"${portId}\") | .id")
    echo "{\"public_ip\":\"${ipaddress}\", \"floating_ip_id\":\"${floatingIp}\"}"
  fi
}

while true; do
  SECONDS=0
  ipdetail=$(getInstanceIp)
  if [[ "$(echo $ipdetail | jq -r '.public_ip')" != "null" ]]; then
    oldip=$(echo $ipdetail | jq -r '.public_ip')
    floatingIp=$(echo $ipdetail | jq -r '.floating_ip_id')
    deleteIp
    echo "old ip: $oldip"
  else
    floatingIp=null
    if [[ "$(echo $listFloatingIp | jq "[.data[] | select(.id != \"${floatingIp}\") | .id] | length")" -gt 0 ]]; then
      for floatingIp in $(echo $listFloatingIp | jq -r ".data[] | select(.id != \"${floatingIp}\") | .id"); do
        echo "detected unused floating ip: $floatingIp"
        deleteIp
      done
    fi
  fi
  sleep 1
  floatingIp=$(createIp | jq -r '.data.id')
  attachIp
  sleep 1
  newIp=$(getInstanceIp | jq -r '.public_ip')
  echo "new ip: $newIp"
  listFloatingIp=$(getFloatingIp)
  #if listFloating ip contain other than floatingIp, delete remaining floating ip
  if [[ "$(echo $listFloatingIp | jq "[.data[] | select(.id != \"${floatingIp}\") | .id] | length")" -gt 0 ]]; then
    for floatingIp in $(echo $listFloatingIp | jq -r ".data[] | select(.id != \"${floatingIp}\") | .id"); do
      echo "detected unused floating ip: $floatingIp"
      deleteIp
    done
  fi
  echo "execution time: $SECONDS"
  echo "execution time: $SECONDS | old ip: $oldip | new ip: $newIp" >>iplistbiznet.txt
  sleep 15
done
