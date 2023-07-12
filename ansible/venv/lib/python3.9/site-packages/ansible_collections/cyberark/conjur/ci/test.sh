#!/bin/bash -ex

# Test runner for Ansible Conjur Collection

# Test subdirectors containing a `test.sh` file
test_directories=("conjur_variable")

# Roles containing a test subdirectory
role_directories=("conjur_host_identity")

# Target directory that can be manually set by passing a value to the `-d` flag
target=""

# Flags to be applied to testing scripts
flags=""

declare -x ANSIBLE_VERSION="${ANSIBLE_VERSION:-6}"

# Print usage instructions
function help {
    echo "Test runner for Ansible Conjur Collection"

    echo "-a        Run all test files in default test directories"
    echo "-v <ver>  Run tests against the given Ansible major version"
    echo "-d <arg>  Run test file in given directory. Valid options are: ${test_directories[*]} all"
    echo "-e        Run tests against Conjur Enterprise. Default: Conjur Open Source"
    echo "          This option is currently only available when testing against the conjur_variable plugin"
    echo "-h        View help and available commands"
    exit 1
}

# Run a `test.sh` file in a given subdirectory of the top-level `tests` directory
# Expected directory structure is "tests/<plugin>/test.sh"
function run_test {
    pushd "${PWD}/tests/${1}"
        echo "Running ${1} tests..."
        ./test.sh "$flags"
    popd
}

# Run a `test.sh` file for a given role
# Expected directory structure is "roles/<role>/tests/test.sh"
function run_role_test {
    pushd "${PWD}/roles/${1}/tests"
        echo "Running ${1} tests..."
        ./test.sh "$flags"
    popd
}

# Handles input to dictate wether all tests should be ran, or just one set
function handle_input {
    if [[ -n ${target} ]]; then
        for test_dir in "${test_directories[@]}"; do
            if [[ ${target} == "${test_dir}" ]]; then
                run_test ${target}
                exit 0
            fi
        done
        for test_dir in "${role_directories[@]}"; do
            if [[ ${target} == "${test_dir}" ]]; then
                run_role_test ${target}
                exit 0
            fi
        done
        echo "Error: unrecognized test directory given: ${target}"
        echo ""
        help
    else
        echo "Running all tests..."
        for test_dir in "${test_directories[@]}"; do
            run_test "${test_dir}"
        done
        for test_dir in "${role_directories[@]}"; do
            run_role_test "${test_dir}"
        done
        exit 0
    fi
}

# Exit if no input given
if [[ $# -eq 0 ]] ; then
    echo "Error: No test directory or flag given"
    echo ""
    help
fi

while getopts ad:ehv: option; do
    case "$option" in
        a) handle_input
            ;;
        d) target=${OPTARG}
           handle_input
            ;;
        e) flags="-e"
            ;;
        h) help
            ;;
        v) ANSIBLE_VERSION="${OPTARG}"
            ;;
        * )
          echo "$1 is not a valid option"
          help
          exit 1
          ;;
    esac
done

