scanapi
=======

scanapi is a small REST API that exposes functionality of a Nessus server to
users or applications. This interface can be used to primarily execute scans
using the Nessus server, and fetch results. The primary intent is provided a
more limited / restricted interface than is possible communicating directly
with the Nessus API, and simplify creating scans and fetching results.

.. code

        < users > --------> < scanapi > --------> < nessus >

Installation
------------

Fetch code
~~~~~~~~~~

.. code :: bash

        $ git clone https://github.com/mozilla/scanapi.git
        $ cd scanapi
        $ virtualenv myenv
        $ source myenv/bin/active
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
