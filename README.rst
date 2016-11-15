scanapi
=======

scanapi is a small REST API that exposes functionality of a Nessus server to
users or applications. This interface can be used to primarily execute scans
using the Nessus server, and fetch results. The primary intent is provided a
more limited / restricted interface than is possible communicating directly
with the Nessus API, and simplify creating scans and fetching results.

::

        < users > --------> < scanapi > --------> < nessus >

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

Copy scanapi.yml.example and edit it as required.

.. code :: bash

        $ cd scanapi
        $ cp scanapi.yml.example scanapi.yml

You will need to create a user in your Nessus server that scanapi will authenticate
to Nessus as, and you need to create API keys for that user. These should be added to
the scanapi configuration file.

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

/api/v1 (GET)
~~~~~~~~~~~~~

Return status.

/api/v1/scan/purge (DELETE)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Purge stored scans and results older than specified timeframe.

/api/v1/scan (POST)
~~~~~~~~~~~~~~~~~~~

Run a new scan with a specified policy against indicated targets.

/api/v1/scan/results (GET)
~~~~~~~~~~~~~~~~~~~~~~~~~~

Fetch the results of a scan, formatted into a JSON document.

/api/v1/scan/policies (GET)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get a list of policies that can be specified when running a scan.

runscan
-------

runscan is a command line tool that can be used to talk to scanapi. You need to set
a couple environment variables.

* SCANAPIURL - Set to URL where scanapi is listening
* SCANAPIKEY - Set to an API key you configured in scanapi.yml if needed
