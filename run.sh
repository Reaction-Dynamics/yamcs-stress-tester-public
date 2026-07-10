#!/bin/bash
set -euo pipefail
# We want to run as the 'remote_user' user, because that is the user that will run
# in container. However, the install sets the SPELL and YAMCS tools up
# to run as the '_yamcs' user. To get around this, we just change the uid:gid
# of the SPELL an YAMCS install folders.
sudo chown -R rdx:rdx /opt/spell /opt/yamcs
cd /avionics/fsw
# Copy over YAMCS config files
mkdir -p /opt/yamcs/etc
cp yamcs.yaml /opt/yamcs/etc/yamcs.yaml
cp yamcs.stressor.yaml /opt/yamcs/etc/yamcs.stressor.yaml
cp processor.yaml /opt/yamcs/etc/processor.yaml
cp logging.properties /opt/yamcs/etc/logging.properties
# Copy over the MDB files
cp -R mdb /opt/yamcs/
#
cd /avionics/fsw
# Make the log directory of the Java logger will fail
sudo mkdir -p /var/log/yamcs
sudo chown rdx:rdx /var/log/yamcs
# Start YAMCS
echo 'Starting YAMCS Server...'
daemon \
   -i \
   -r -M 4 \
   -e "YAMCS_DATA_DIR=/home/rdx/yamcs-data" \
   -e "YAMCS_CACHE_DIR=/home/rdx/yamcs-cache" \
   -e "JAVA_OPTS=-Xmx8g" \
   /opt/yamcs/bin/yamcsd &

# Wait for YAMCS to be ready before tailing it's log
# NOTE:
#   - If the server is not running we get exit code 7
#   - If the server is running we get exit code 0 if authentication isn't
#     enforced, or, 22 is it is (because we don't send any credentials so
#     the request to the /api endpoint which needs authentication will fail)
echo "Waiting for YAMCS to be ready..."

while true; do
   set +e
   curl -sf http://localhost:8090/api/ > /dev/null 2>&1
   exit_code=$?
   set -e
   if [[ ${exit_code} -eq 0 || ${exit_code} -eq 22 ]]; then
      break
   fi
   sleep 2
done
echo "YAMCS is ready."

# echo "Starting set_cpu_affinity.sh script..."
# sudo daemon \
#   -i \
#   -r \
#   --unsafe \
#   /avionics/fsw/set_cpu_affinity.sh  # Needs abs path!!!

# Spin here so the container doesn't exit
echo 'Tailing /var/log/yamcs.log until container is stopped...'
# Make the log file to tail in case it isn't made yet.
sudo touch /var/log/yamcs/yamcs.log
sudo chown rdx:rdx /var/log/yamcs/yamcs.log
tail -n +1 -f /var/log/yamcs/yamcs.log
