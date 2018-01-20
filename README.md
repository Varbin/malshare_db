# MalShare database server
Conversion of htttps://malshare.com hashes to ClamAV databases

## Standarts

The script conforms to
[PEP-8](https://www.python.org/dev/peps/pep-0008/) (Python style guide) and
[PEP-3333](https://www.python.org/dev/peps/pep-3333/) (WSGI).

## Installation

`pip install git+https://github.com/Varbin/malshare_db`

Requirements are installed automatically.

### Requirements:
 - [portalocker](https://pypi.org/project/portalocker/)
 - [requests](https://pypi.org/project/requests/)

Optional:
 - [requests-cache](https://pypi.org/project/requests-cache/) for increased speed.
 - [aiohttp](https://pypi.org/project/aiohttp/) + [aiohttp_wsgi](https://pypi.python.org/pypi/aiohttp_wsgi/)

## Documentation


MalShare to ClamAV converter

Usage: `malshare_db.py [--help|--version|--cgi|--fcgi[-server]|--wsgi(ref|aio)|--offline]`

Command line arguments:

    --help     Show this message and exit.
    --version  Show script version and installed capabilities.

    --cgi      Run this script as CGI script.
    --fcgi     Run this script as FastCGI script (for e.g. FastCGI spawn).
    --fcgi-server  Run this script as FastCGI  server on 127.0.0.1:9000 (see WSGI_HOST and WSGI_PORT).
    --wsgiref  Start this script on the WSGI reference server on 127.0.0.1:8000 (see WSGI_HOST and WSGI_PORT).
    --wsgiaio  Start this script on the aiohttp WSGI adapter on 127.0.0.1:8000 (see WSGI_HOST and WSGI_PORT).

    --offline  (Default) Update "MalShare.hdb" in the current directory.


For --fcgi and --fcgi-server one of the packages flup (Python < 3), flup6 (Python >= 3) or flipflop (also Python >= 3) is required. The package flipflop does not support --fcgi-server.

When using --fcgi only a small portion of the main database can be downloaded (bug). With --fcgi-server the main database download is really slow (low latency, but also low throughput and a high CPU usage).

The --wsgiref option also validates the script if it is conforming to the WSGI standart. Do not use --wsgiref in production, use a proper WSGI server. While it has a decent speed, it can exhaust resources quite fast and might have security vulnerabilities. USE --wsgiref FOR TESTING ONLY!

Using the --wsgiaio flag requires the packages aiohttp and aiohttp_wsgi to be installed.


Environment variables:

    DEBUG           Enables debug output to stderr

    WSGI_HOST=host  Defines the hostname for servers (HTTP or FCGI).
        Default: 127.0.0.1
    WSGI_PORT=port  Defines the port for servers (HTTP or FCGI).
        Default: 8000 for HTTP; 9000 for FastCGI

    WSGI_PATH_STRIP=path    Strips path from the beginning of a request path. This is a hack as some webservers do not allow stripping  the beginning of a path. Implementation detail: Additional endpoints starting with path are added.

Optimizations:
 - Install requests-cache. This will enable caching the MalShare-current.* files. The cache is on a per-process-basis for security reasons, so the cache must be initialized for each process in multiprocess deployments. There will be no benefits if the application is only executed once for each request (e.g. CGI) as the cache is not shared. If security problems are solved within requests-cache then a shared cache might be readded.

 - Use an external WSGI server for deployment. uWSGI and gunicorn both seem to be a good choice. This script offers the common entrypoints for WSGI server 'app' and 'application'. For aiohttp deployments 'aioapp' is defined. See below for examples.

Examples:

    Deployment without external server:
        PATH_STRIP=/malshare WSGI_PORT=1234 malshare_db.py --wsgiref
        - Start this script on the WSGIref server on http://127.0.0.1:1234.
        - Valid requests:
            http://127.0.0.1:8080/MalShare.hdb
            http://127.0.0.1:8080/MalShare-current.hdb
            http://127.0.0.1:8080/MalShare-current.hsb
            http://127.0.0.1:8080/malshare/MalShare.hdb
            ...

    Deployment with externel server (e.g. uWSGI, Gunicorn):
        uwsgi --http-socket 127.0.0.1:1234 malshare_db.py
        - Start this script on uWSGI on http://127.0.0.1:1234.

        gunicorn -k aiohttp.GunicornWebWorker -b 127.0.0.1:1234 malshare_db:aioapp
        - Start this script on Gunicorn with aiohttp on http://127.0.0.1:1234.


