#!/usr/bin/env python3
"""
MalShare to ClamAV converter

Usage: malshare_db.py \
[--help|--version|--cgi|--fcgi[-server]|--wsgi(ref|aio)|--offline]

Command line arguments:
    --help     Show this message and exit.
    --version  Show script version and installed capabilities.

    --cgi      Run this script as CGI script.
    --fcgi     Run this script as FastCGI script \
(for e.g. FastCGI spawn).
    --fcgi-server  Run this script as FastCGI  server on \
127.0.0.1:9000 (see WSGI_HOST and WSGI_PORT).
    --wsgiref  Start this script on the WSGI reference server on \
127.0.0.1:8000 (see WSGI_HOST and WSGI_PORT).
    --wsgiaio  Start this script on the aiohttp WSGI adapter on \
127.0.0.1:8000 (see WSGI_HOST and WSGI_PORT).

    --offline  (Default) Update "MalShare.hdb" in the \
current directory.


For --fcgi and --fcgi-server one of the packages \
flup (Python < 3), flup6 (Python >= 3) or \
flipflop (also Python >= 3) is required. \
The package flipflop does not support --fcgi-server.

When using --fcgi only a small portion of the main database \
can be downloaded (bug). \
With --fcgi-server the main database download is really slow \
(low latency, but also low throughput and a high CPU usage).

The --wsgiref option also validates the script if it is \
conforming to the WSGI standart. Do not use --wsgiref in \
production, use a proper WSGI server. While it has a \
decent speed, it can exhaust resources quite fast and might \
have security vulnerabilities. USE --wsgiref FOR TESTING ONLY!

Using the --wsgiaio flag requires the packages aiohttp and \
aiohttp_wsgi to be installed.


Environment variables:
    DEBUG           Enables debug output to stderr

    WSGI_HOST=host  Defines the hostname for servers (HTTP or FCGI).
        Default: 127.0.0.1
    WSGI_PORT=port  Defines the port for servers (HTTP or FCGI).
        Default: 8000 for HTTP; 9000 for FastCGI

    WSGI_PATH_STRIP=path    Strips path from the beginning \
of a request path. This is hack as some webservers do not \
allow stripping  the beginning of a path. Implementation detail: \
Additional endpoints starting with path are added.

Optimizations:
    - Install requests-cache. This will enable caching the \
MalShare-current.* files. The cache is on a per-process-basis \
for security reasons, so the cache must be initialized for each process \
in multiprocess deployments. There will be no benefits if the \
application is only executed once for each request (e.g. CGI) as \
the cache is not shared. If security problems are solved within \
requests-cache then a shared cache might be readded.

    - Use an external WSGI server for deployment. uWSGI and \
gunicorn both seem to be a good choice. This script offers the \
common entrypoints for WSGI 'app' and 'application'. For aiohttp \
deployments 'aioapp' is defined. See below for \
examples.

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

        gunicorn -k aiohttp.GunicornWebWorker -b 127.0.0.1:1234 \
malshare_db:aioapp
        - Start this script on Gunicorn with aiohttp on \
http://127.0.0.1:1234.
"""

__version__ = "0.1"

from datetime import date, timedelta, datetime
from wsgiref.handlers import CGIHandler
from wsgiref.simple_server import make_server
from wsgiref.validate import validator

import itertools
import logging
import os
import sys

import portalocker
import requests

try:
    import aiohttp
    from aiohttp import web
    from aiohttp.log import access_logger
    import aiohttp_wsgi
    from aiohttp_wsgi import WSGIHandler
except ImportError:
    AIOHTTP = False
else:
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    AIOHTTP = True

try:
    import requests_cache
except ImportError:
    REQUESTS_CACHE = False
else:
    requests_cache.install_cache(backend='memory', expire_after=1800)
    REQUESTS_CACHE = True

DEBUG = os.environ.get("DEBUG") is not None

SESSION = requests.Session()
SESSION.headers["User-Agent"] = (
    "MalSh-CAV/0.5 See https://sbiewald.de/malsh-cav {}".format(
        SESSION.headers["User-Agent"]))

URL_CURRENT = "https://malshare.com/daily/malshare.current{suffix}.txt"
URL_REGULAR = ("https://malshare.com/daily/" +
               "{old}{date}/malshare_fileList.{date}{suffix}.txt")

DATABASE_LINE = "{sig}:*:MalShare.{tag}-{n}{suffix}:73"

MESSAGE_BAD_GATEWAY = """\
503 Bad Gateway

The connection to the remote gateway failed.


Error type: {}
"""

ERROR_NOT_FOUND = ("404 Not Found", [("Content-Type", "text/plain"),
                                     ("Content-Length", "13")],
                   [b"404 Not Found"])


def daterange(start, stop):
    "Creates a genrator which returns dates from start to stop."
    for i in range(abs((start - stop).days)):
        yield timedelta(days=i) + min(start, stop)


def hash_to_db(lines, tag, suffix, template=DATABASE_LINE):
    """
    Converts an iterable of strings into a simple ClamAV database.

    The created signatures are in the following form by default:
        {sig}:*:MalShare.{tag}-{n}{suffix}:73

    lines (list of strings): List of the signatures
    tag (string): How to "name" all signatures.
    suffix (string): Second "name" for the signatures.
    template (string): formatable string for the conversion
    """
    set_lines = itertools.takewhile(bool, lines)
    return "\n".join(
        template.format(sig=line, tag=tag, n=n, suffix=suffix)
        for n, line in enumerate(set_lines))


def _date_from_db(line):
    "Reads a name out of a line of converted MalShare datases."

    name = line.split(":")[2]
    return datetime.strptime((name.split(".")[1].split("-")[0]),
                             "%Y%m%d").date()


def malshare_by_date(pub_date=None, suffix=""):
    """Download a single day's MalShare hashes and convert them.

    pub_data (date object): The date.
    suffix (string): A suffix to add to the signatures name.\
        Usefull to indicate a different algorithm.
    """

    if pub_date is None:
        pub_date = date.today() - timedelta(days=1)

    isodate = str(pub_date)
    shortdate = isodate.replace("-", "")

    url = URL_REGULAR.format(
        date=isodate,
        old=""
        if pub_date > date(year=2017, month=9, day=12) else "_disabled/",
        suffix=suffix)

    response = SESSION.get(url)

    if DEBUG:
        sys.stderr.write(
            "--GET " + url + " " + str(response.status_code) + "\n")

    response.raise_for_status()

    return hash_to_db(response.text.splitlines(), shortdate, suffix)


def malshare_by_dates(start=None, stop=None, suffix="", silent=False):
    """Downloads MalShare database from start to stop.

    start (date or None): The start date. None equals today - 1 day.
    stop (date or None): The stop date. None equals today - 15 days,
    suffix (string): A suffix to add to the signatures name.\
        Usefull to indicate a different algorithm.
    silent (boolean): Silence any errors (skip days with errors).
    """

    if start is None:
        start = date.today() - timedelta(days=1)
    if stop is None:
        stop = date.today() - timedelta(days=15)

    dates = sorted(set(list(daterange(start, stop)) + [max(start, stop)]))

    out = []

    for date_ in dates:
        try:
            out.append(malshare_by_date(date_, suffix))
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError):
            if not silent:
                raise

    return "\n".join(out).replace("\n\n", "\n").replace("\n\n", "\n")


def malshare_current(suffix="", forward=None):
    "Download today's MalShare signatures"
    response = SESSION.get(
        URL_CURRENT.format(suffix=suffix), headers={
            "X-Forward-For": forward
        })
    response.raise_for_status()

    database = hash_to_db(response.text.splitlines(),
                          str(date.today()).replace("-", "") + ".c", suffix)
    cached = False
    if hasattr(response, "from_cache"):
        cached = response.from_cache
    return database, cached


def malshare_update(filename, suffix=""):
    "Update a ClamAV database with MalShare signatures."
    with portalocker.Lock(filename, "ab+") as db_file:
        db_file.seek(0)
        if db_file.readline():
            db_file.seek(-200, os.SEEK_END)
            last_line = db_file.readlines()[-1]
            if not last_line.endswith(b"\n"):
                db_file.write(b"\n")
            old_date = _date_from_db(last_line.decode())

        else:
            old_date = date.today() - timedelta(days=16)

        if old_date in (date.today(), date.today() - timedelta(days=1)):
            return False

        if DEBUG:
            sys.stderr.write(" ".join([
                "Update ",
                str(old_date),
                str(date.today() - timedelta(days=1)), "\n"
            ]))

        db_file.write(
            malshare_by_dates(
                stop=old_date + timedelta(days=1), suffix=suffix,
                silent=True).encode())

        if REQUESTS_CACHE:
            requests_cache.clear()

        return True


def app(environ, start_response, strip=os.environ.get("WSGI_PATH_STRIP", "")):
    """WSGI application object for distributing MalShare's database.

    Endpoints:
        /MalShare.hdb
        /MalShare-current.hdb
        /MalShare-current.hsb

    environ (dict): WSGI environment

    start_response (callable(status, headers)):
        Starts the WSGI response.

    strip (string): Strips this at the start of every requests' path.
        Defaults os.environ["WSGI_PATH_STRIP"] or "".

    Returns:
        Iterable returning bytes.
    """
    status = '200 OK'
    headers = [("Content-Type", "text/plain")]

    path_info = environ.get("PATH_INFO")
    if strip and path_info.startswith(strip):
        path_info = path_info[len(strip):]

    request_method = environ.get("REQUEST_METHOD")
    valid_paths = ("/MalShare-current.hdb", "/MalShare-current.hsb",
                   "/MalShare.hdb")

    if request_method not in ("GET", "OPTIONS"):
        status = '405 Method Not Allowed'
        headers += [("Content-Length", "35"), ("Allow", "GET, OPTIONS")]
        msg = [b'405 Method Not Allowed\nAllowed: GET']
    elif path_info not in valid_paths:
        status, headers, msg = ERROR_NOT_FOUND
    elif request_method == ("OPTIONS"):
        headers = [("Allow", "GET, OPTIONS"), ("Content-Length", "0")]
        msg = []
    elif path_info.partition(".")[0] == "/MalShare-current":
        if path_info.partition(".")[2] == "hdb":
            suffix = ""
        elif path_info.partition(".")[2] == "hsb":
            suffix = ".sha1"
        else:
            status, headers, msg = ERROR_NOT_FOUND
        if not status.startswith("404"):
            try:
                msg, cached = malshare_current(
                    suffix,
                    (environ.get("HTTP_X_FORWARDED_FOR") or
                     environ.get("REMOTE_HOST")))
                msg = [msg.encode()]
            except requests.RequestException as error:
                msg = [
                    MESSAGE_BAD_GATEWAY.format(
                        error.__class__.__name__).encode()
                ]
                cached = False
                # Does not work with flup (just blocks):
                #  traceback.print_exc(file=environ["wsgi.errors"])
                status = "503 Bad Gateway"

            length = str(len(msg[0]))
            headers += [("Content-Length", length)]
            if REQUESTS_CACHE:
                headers += [("X-Cache-Hit", str(cached))]
    elif path_info == "/MalShare.hdb":
        malshare_update("MalShare.hdb")
        length = str(os.path.getsize("MalShare.hdb"))
        headers += [("Content-Length", length)]
        headers += [("Content-Disposition", "attachment")]
        msg = open("MalShare.hdb", "rb")

        if environ.get("wsgi.file_wrapper"):
            msg = environ["wsgi.file_wrapper"](msg)

    else:
        status = "500 Server Error"
        msg = [b"Internal Server\n\nUnhandled status."]

    start_response(status, headers)
    return msg


application = app  # pylint: disable=invalid-name
validated_app = validator(app)  # pylint: disable=invalid-name

if AIOHTTP:
    aioapp = web.Application()  # pylint: disable=invalid-name
    aioapp.router.add_route("*", "/{path_info:.*}",
                            WSGIHandler(app))


if __name__ == "__main__":
    if len(sys.argv) > 2 or "--help" in sys.argv:
        print(__doc__)
        sys.exit(1)

    if "--version" in sys.argv:
        print("Version:", __version__)
        print()
        print("Dependencies:")
        print(" - requests:", requests.__version__)
        print(" - portalocker:", portalocker.__version__)
        print()
        print("Optional dependencies:")
        print(" - requests-cache:", end=' ')
        print(("not installed"
               "") if not REQUESTS_CACHE else requests_cache.__version__)
        print()
        print(" - aiohttp:", end=' ')
        print("not installed" if not AIOHTTP else aiohttp.__version__)
        print(" - aiohttp_wsgi:", end=' ')
        print(("not installed or aiohttp missing"
               "") if not AIOHTTP else aiohttp_wsgi.__version__)
        sys.exit(0)

    WSGI_HOST = os.environ.get("WSGI_HOST", "127.0.0.1") or "127.0.0.1"
    WSGI_PORT = os.environ.get("WSGI_PORT", None)

    if WSGI_PORT is not None:
        try:
            WSGI_PORT = int(WSGI_PORT)
        except ValueError:
            sys.stderr.write("Error: WSGI_PORT is not a number!\n")
            sys.exit(1)

    if any(arg.startswith("--wsgi") for arg in sys.argv):
        WSGI_PORT = WSGI_PORT or 8000
        sys.stderr.write("Serving on {}:{}...\n".format(WSGI_HOST, WSGI_PORT))
    elif "--fcgi-server" in sys.argv:
        WSGI_PORT = WSGI_PORT or 9000
        sys.stderr.write("Serving on {}:{}...\n".format(WSGI_HOST, WSGI_PORT))

    if "--cgi" in sys.argv:
        CGIHandler().run(app)
    elif "--fcgi" in sys.argv or "--fcgi-server" in sys.argv:
        WSGIServer = None  # pylint: disable=invalid-name
        try:
            from flup.server.fcgi import WSGIServer
        except ImportError:
            try:
                if "--fcgi" in sys.argv:
                    from flipflop import WSGIServer
                else:
                    raise ImportError
            except ImportError:
                pass
            else:
                sys.stderr.write("FastCGI server: FlipFlop\n")
        else:
            sys.stderr.write("FastCGI server: Flup/Flup6\n")

        if WSGIServer is None:
            sys.stderr.write("Error: No FastCGI server found.\n")
            sys.exit(2)

        if "--fcgi-server" in sys.argv:
            server = WSGIServer(  # pylint: disable=invalid-name
                app, bindAddress=(WSGI_HOST, WSGI_PORT))
        else:
            server = WSGIServer(app)  # pylint: disable=invalid-name

        server.run()
    elif "--wsgiref" in sys.argv:
        httpd = make_server(  # pylint: disable=invalid-name
            WSGI_HOST, WSGI_PORT or 8000, validated_app)
        httpd.serve_forever()
    elif "--wsgiaio" in sys.argv:
        if not AIOHTTP:
            sys.stderr.write("Error: aiohttp or aiohttp_wsgi not found!\n")
            sys.exit(2)

        logging.basicConfig(format="%(message)s")
        logging.getLogger("aiohttp").setLevel(logging.INFO)

        loop = asyncio.get_event_loop()  # pylint: disable=invalid-name
        handler = aioapp.make_handler(  # pylint: disable=invalid-name
            access_log=access_logger)
        srv = loop.run_until_complete(  # pylint: disable=invalid-name
            loop.create_server(handler, WSGI_HOST, WSGI_PORT))

        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            srv.close()
            loop.run_until_complete(srv.wait_closed())
            loop.run_until_complete(aioapp.shutdown())
            loop.run_until_complete(handler.shutdown(60.0))
            loop.run_until_complete(aioapp.cleanup())
            loop.close()

    else:
        print("MalShare to ClamAV converter")
        print()
        print("DB file:")
        print(os.path.abspath("MalShare.hdb"))
        print()
        if not malshare_update(os.path.abspath("MalShare.hdb")):
            print("Database is up to date ;)")
        else:
            print("Database update successfull ;)")
