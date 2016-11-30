scanapi
=======

scanapi is a small REST API that exposes functionality of a Nessus server to
users or applications. This interface can be used to primarily execute scans
using the Nessus server, and fetch results. The primary intent is to provide a
more limited / restricted interface than is possible communicating directly
with the Nessus API, and simplify creating scans and fetching results.

::

        < users > --------> < scanapi > --------> < nessus >

The repo contains two primary components.

scanapi
-------

This is the API itself which will interact with Nessus on your behalf. You can
install or run this if you want to run your own API instance.

runscan
-------

This is a command line tool that can be used to interact with an existing scanapi
instance, to create scans or fetch results from the instance. Using runscan is not
required if you want to interact with scanapi yourself by making your own requests.

Installation
------------

Fetch code
~~~~~~~~~~

.. code :: bash

        $ git clone https://github.com/mozilla/scanapi.git
        $ cd scanapi
        $ virtualenv myenv
        $ source myenv/bin/activate
        $ pip install -r requirements.txt

Configure scanapi
~~~~~~~~~~~~~~~~~

If you want to run your own scanapi API instance, it needs to be configured to
interact with the Nessus server. If you just want runscan, skip to the later
documentation section.

Copy scanapi.yml.example and edit it as required.

.. code :: bash

        $ cd scanapi
        $ cp scanapi.yml.example scanapi.yml

You will need to create a user in your Nessus server that scanapi will authenticate
to Nessus as, and you need to create Nessus API keys for that user (generally done in
the Nessus console). These keys should be added to the scanapi configuration file.

The ``zone`` value can be set to a name that will be included in the result set, to
differentiate the results from other instances of scanapi that may be running.

The ``appkeys`` section can be used to specify application keys, one of which
must be sent in the SCANAPIKEY header to authenticate when making requests to the
API. If no ``appkeys`` section is present, no authentication against scanapi will
occur.

Run scanapi
~~~~~~~~~~~

scanapi can be run directly for testing.

.. code :: bash

        $ ./scanapi.py

For actual use, you would generally configure it with nginx and uwsgi.

API endpoints
-------------

Supported API endpoints in scanapi, see scanapi or runscan code for details. All API responses
are returned as JSON, with the exception of the raw CSV report request which is returned as text.

/api/v1 (GET)
~~~~~~~~~~~~~

Parameters:

* None

Return status.

/api/v1/scan/purge (DELETE)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Purges any old scans created by scanapi from Nessus.

Parameters:

* ``olderthan``: Integer, specifies minimum age in seconds of scans to be purged

Returns a status message.

/api/v1/scan (POST)
~~~~~~~~~~~~~~~~~~~

Create a new scan in Nessus, against the indicated targets using the indicated policy.

Parameters:

* ``targets``: Comma separated list of IP addresses or hostnames to scan
* ``policy``: A policy name, list of available policies can be queries via the policies endpoint

Returns a scan ID which can be used to fetch results.

/api/v1/scan/results (GET)
~~~~~~~~~~~~~~~~~~~~~~~~~~

Fetch the results of a scan, formatted into a JSON document.

Parameters:

* ``scanid``: UUID, the scan ID to get results for
* ``mincvss``: Float, instructs scanapi to only include vulnerabilities >= mincvss
* ``nooutput``: If set, plugin output will not be included in the results

Returns JSON formatted results.

/api/v1/scan/results/csv (GET)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Fetch the raw CSV results of a scan.

Parameters:

* ``scanid``: UUID, the scan ID to get results for

Returns text content CSV report.

/api/v1/scan/policies (GET)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get a list of policies that can be specified when running a scan.

Parameters:

* None

Returns list of available policies.

runscan
-------

runscan is a command line tool that can be used to talk to scanapi. You need to set
a couple environment variables. You need to ensure the requirements listed in
``requirements.txt`` are installed, either globally or in a virtualenv to run
runscan.

* SCANAPIURL - Set to URL where scanapi is listening
* SCANAPIKEY - Set to an API key you configured in scanapi.yml if needed

::

        $ ./runscan.py -h
        usage: runscan.py [-h] [--capath capath] [--csv]
                  [--filter-subnets subnetsfile] [--mozdef mozdefurl]
                  [--mincvss cvss] [--nooutput] [--serviceapi sapiurl]
                  [-s targets] [-p policy] [-D seconds] [-f] [-P] [-r scan id]
        
        optional arguments:
        -h, --help            show this help message and exit
        --capath capath       path to ca certificate
        --csv                 fetch raw results in csv format instead of modified
                              json
        --filter-subnets subnetsfile
                              filter any ip in target list that matches a subnet in
                              subnetsfile
        --mozdef mozdefurl    emit results as vulnerability events to mozdef, use
                              'stdout' as url to just print json to stdout
        --mincvss cvss        filter vulnerabilities below specified cvss score
        --nooutput            don't include plugin output in results
        --serviceapi sapiurl  integrate with serviceapi for host ownership and
                              indicators, used when fetching results
        -s targets            run scan on comma separated targets, can also be
                              filename with targets
        -p policy             policy to use when running scan
        -D seconds            purge scans older than argument, must be >= 300
        -f                    follow scan until complete and get results
        -P                    list policies
        -r scan id            fetch results
        
        The targets parameter can either contain a comma separated list of targets, or
        a path to a file containing a target list. If a file is used, it should
        contain one target per line.

