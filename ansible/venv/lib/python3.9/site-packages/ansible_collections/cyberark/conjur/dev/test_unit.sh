#!/bin/bash -eu

ansible_version="stable-2.10"
python_version="3.9"
gen_report="false"

cd "$(dirname "$0")"/..

function print_usage() {
   cat << EOF
Run unit tests for Conjur Variable Lookup plugin.

./ansibletest.sh [options]

-a <version>     Run tests against specified Ansible version (Default: stable-2.10)
-p <version>     Run tests against specified Python version  (Default: 3.9)
-r               Generate test coverage report
EOF
}

while getopts 'a:p:r' flag; do
  case "${flag}" in
    a) ansible_version="${OPTARG}" ;;
    p) python_version="${OPTARG}" ;;
    r) gen_report="true" ;;
    *) print_usage
       exit 1 ;;
   esac
done

test_cmd="ansible-test units -v --python $python_version"
if [[ "$gen_report" == "true" ]]; then
  test_cmd="ansible-test coverage erase;
    $test_cmd --coverage;
    ansible-test coverage html --requirements --group-by command;
  "
fi

docker build \
  --build-arg PYTHON_VERSION="${python_version}" \
  --build-arg ANSIBLE_VERSION="${ansible_version}" \
  -t pytest-tools:latest \
  -f tests/unit/Dockerfile .
docker run --rm \
  -v "${PWD}/":/ansible_collections/cyberark/conjur/ \
  -w /ansible_collections/cyberark/conjur/tests/unit/ \
  pytest-tools:latest /bin/bash -c "$test_cmd"
