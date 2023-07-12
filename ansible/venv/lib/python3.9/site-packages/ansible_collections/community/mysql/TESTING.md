# Tests

This collection uses GitHub Actions to run ansible-test to validate its content. Three type of tests are used: Sanity, Integration and Units.

The tests covers plugins and roles (no role available yet, but tests are ready) and can be found here:

- Plugins: *.github/workflows/ansible-test-plugins.yml*
- Roles: *.github/workflows/ansible-test-roles.yml* (unused yet)

Everytime you push on your fork or you create a pull request, both workflows runs. You can see the output on the "Actions" tab.


## Integration tests

You can use GitHub to run ansible-test either on the community repo or your fork. But sometimes you want to quickly test a single version or a single target. To do that, you can use the Makefile present at the root of this repository.

For now, the makefile only supports Podman.


### Requirements

- python >= 3.8 and <= 3.10
- make
- podman
- Minimum 15GB of free space on the device storing containers images and volumes. You can use this command to check: `podman system info --format='{{.Store.GraphRoot}}'|xargs findmnt --noheadings --nofsroot --output SOURCE --target|xargs df -h --output=size,used,avail,pcent,target`
- Minimum 2GB of RAM


### Custom ansible-test containers

Our integrations tests use custom containers for ansible-test. Those images have their definition file stored in the directory [test-containers](test-containers/). We build and publish the images on ghcr.io under the ansible-collection namespace: E.G.:
`ghcr.io/ansible-collections/community.mysql/test-container-mariadb106-py310-mysqlclient211:latest`.

Availables images are listed [here](https://github.com/orgs/ansible-collections/packages).


### Makefile options

The Makefile accept the following options

- `local_python_version`
  - Mandatory: false
  - Choices:
    - "3.8"
    - "3.9"
    - "3.10"
  - Description: If `Python -V` shows an unsupported version, use this option and choose one of the version available on your system. Use `ls /usr/bin/python3*|grep -v config` to list them.

- `ansible`
  - Mandatory: true
  - Choices:
    - "stable-2.12"
    - "stable-2.13"
    - "stable-2.14"
    - "devel"
  - Description: Version of ansible to install in a venv to run ansible-test

- `db_engine_name`
  - Mandatory: true
  - Choices:
    - "mysql"
    - "mariadb"
  - Description: The name of the database engine to use for the service containers that will host a primary database and two replicas.

- `db_engine_version`
  - Mandatory: true
  - Choices:
    - "5.7.40" <- mysql
    - "8.0.31" <- mysql
    - "10.4.24" <- mariadb
    - "10.5.18" <- mariadb
    - "10.6.11" <- mariadb
  - Description: The tag of the container to use for the service containers that will host a primary database and two replicas. Do not use short version, like `mysql:8` (don't do that) because our tests expect a full version to filter tests precisely. For instance: `when: db_version is version ('8.0.22', '>')`. You can use any tag available on [hub.docker.com/_/mysql](https://hub.docker.com/_/mysql) and [hub.docker.com/_/mariadb](https://hub.docker.com/_/mariadb) but GitHub Action will only use the versions listed above.

- `connector_name`
  - Mandatory: true
  - Choices:
    - "pymysql
    - "mysqlclient"
  - Description: The python package of the connector to use. In addition to selecting the test container, this value is also used for tests filtering: `when: connector_name == 'pymysql'`.

- `connector_version`
  - Mandatory: true
  - Choices:
    - "0.7.11" <- pymysql (Only for MySQL 5.7)
    - "0.9.3" <- pymysql
    - "1.0.2" <- pymysql
    - "2.0.1" <- mysqlclient
    - "2.0.3" <- mysqlclient
    - "2.1.1" <- mysqlclient
  - Description: The version of the python package of the connector to use. This value is used to filter tests meant for other connectors.

- `python`
  - Mandatory: true
  - Choices:
    - "3.8"
    - "3.9"
    - "3.10"
  - Description: The python version to use in the controller (ansible-test container).

- `target`
  - Mandatory: false
  - Choices:
    - "test_mysql_db"
    - "test_mysql_info"
    - "test_mysql_query"
    - "test_mysql_replication"
    - "test_mysql_role"
    - "test_mysql_user"
    - "test_mysql_variables"
  - Description: If omitted, all test targets will run. But you can limit the tests to a single target to speed up your tests.

- `keep_containers_alive`
  - Mandatory: false
  - Description: This option keeps all tree databases containers and the ansible-test container alive at the end of tests or in case of failure. This is useful to enter one of the containers with `podman exec -it <container-name> bash` for debugging. Rerunning the
tests will overwrite the 3 databases containers so no need to kill them in advance. But nothing will kill the ansible-test container. You must do that using `podman stop` and `podman rm`. Add any value to activate this option: `keep_containers_alive=1`

- `continue_on_errors`
  - Mandatory: false
  - Description: Tells ansible-test to retry on errors and also continue on errors. This is the way the GitHub Action's workflow runs the tests. This can be used to catch all errors in a single run, but you'll need to scroll up to find them. Add any value to activate this option: `continue_on_errors=1`


#### Makefile usage examples:

```sh
# Run all targets
make ansible="stable-2.12" db_engine_name="mysql" db_engine_version="5.7.40" python="3.8" connector_name="pymysql" connector_version="0.7.11"

# A single target
make ansible="stable-2.14" db_engine_name="mysql" db_engine_version="5.7.40" python="3.8" connector_name="pymysql" connector_version="0.7.11" target="test_mysql_info"

# Keep databases and ansible tests containers alives
# A single target and continue on errors
make ansible="stable-2.14" db_engine_name="mysql" db_engine_version="8.0.31" python="3.9" connector_name="mysqlclient" connector_version="2.0.3" target="test_mysql_query" keep_containers_alive=1 continue_on_errors=1

# If your system has an usupported version of Python:
make local_python_version="3.8" ansible="stable-2.14" db_engine_name="mariadb" db_engine_version="10.6.11" python="3.9" connector_name="pymysql" connector_version="0.9.3"
```


### Run all tests

GitHub Action offer a test matrix that run every combination of Python, MySQL, MariaDB and Connector against each other. To reproduce this, this repo provides a script called *run_all_tests.py*.

Examples:

```sh
python run_all_tests.py
```


### Add a new Python, Connector or Database version

You can look into `[.github/workflows/ansible-test-plugins.yml](https://github.com/ansible-collections/community.mysql/tree/main/.github/workflows)` to see how those containers are built using [build-docker-image.yml](https://github.com/ansible-collections/community.mysql/blob/main/.github/workflows/build-docker-image.yml) and all [docker-image-xxx.yml](https://github.com/ansible-collections/community.mysql/blob/main/.github/workflows/docker-image-mariadb103-py38-mysqlclient201.yml) files.

1. Add a workflow in [.github/workflows/](.github/workflows)
1. Add a new folder in [test-containers](test-containers) containing a new Dockerfile. Your container must contains 3 things:
  - Python
  - A connector: The python package to connect to the database (pymysql, mysqlclient, ...)
  - A mysql client to prepare databases before our tests starts. This client must provide both `mysql` and `mysqldump` commands.
1. Add your version in the matrix of *.github/workflows/ansible-test-plugins.yml*. You can use [run_all_tests.py](run_all_tests.py) to help you see what the matrix will be. Simply comment out the line `os.system(make_cmd)` before runing the script. You can also add `print(len(matrix))` to display how many tests there will be on GitHub Action.
1. Ask the lead maintainer to mark your new image(s) as `public` under [https://github.com/orgs/ansible-collections/packages](https://github.com/orgs/ansible-collections/packages)

After pushing your commit to the remote, the container will be built and published on ghcr.io. Have a look in the "Action" tab to see if it worked. In case of error `failed to copy: io: read/write on closed pipe` re-run the workflow, this append unfortunately a lot.

To see the docker image produced, go to the package page in the ansible-collection namespace [https://github.com/orgs/ansible-collections/packages](https://github.com/orgs/ansible-collections/packages). This page indicate a "Published x days ago" that is updated infrequently. To see the last time the container has been updated you must click on its title and look in the right hands side bellow the title "Last published".
