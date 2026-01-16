#!/bin/python3

# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name

"""Entry point script for running the CMP test suite in a Docker container.

It aims to simplify the user experience, by exposing a minimal command line interface
for doing simple things (e.g., run smoke tests), while also allowing complex use cases,
when necessary (e.g., run all tests with a custom configuration).
"""

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger("cmptest")


def get_version():
    """Read the version from the VERSION file."""
    version_file = Path(__file__).parent.parent / "VERSION"
    try:
        with open(version_file, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "unknown"


def valid_url(arg):
    """Check whether the given URL is valid."""
    url = urlparse(arg)
    if all((url.scheme, url.netloc)):
        return arg
    raise argparse.ArgumentTypeError("Invalid URL")


def run_robot_command(command, verbose=False):
    """Run the robot command and return its exit code."""
    if verbose:
        log.info("Run: %s", command)
    try:
        with subprocess.Popen(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
        ) as process:
            # Stream output in real-time
            while True:
                stdout_line = process.stdout.readline()
                stderr_line = process.stderr.readline()

                if stdout_line:
                    log.info(stdout_line.strip())
                if stderr_line:
                    log.error(stderr_line.strip())

                if not stdout_line and not stderr_line and process.poll() is not None:
                    break

            exit_code = process.poll()
            log.info("Command completed with exit code: %s", exit_code)
            return exit_code
    except OSError as e:
        log.error("Error executing command: %s", e)
        return 1


def start_mock_ca(port: int, verbose: bool) -> Optional[subprocess.CompletedProcess[bytes]]:
    """Start the Mock CA server with the provided port.

    :param port: The port to use for the Mock CA server.
    :param verbose: Whether to display additional information.
    :return: The subprocess object if successful, None otherwise.
    """
    command = [
        sys.executable,
        "mock_ca/ca_handler.py",
        "--host",
        "0.0.0.0",
        "--port",
        str(port),
    ]
    if verbose:
        log.info("Starting Mock CA: %s", " ".join(command))
    try:
        return subprocess.run(command, check=False)

    except KeyboardInterrupt:
        return None

    except OSError as e:
        log.error("Error starting Mock CA: %s", e)
        return None


class CustomConfigAction(argparse.Action):
    """
    Custom argparse action to handle the --customconfig argument.

    Distinguishes between explicit usage (with or without a value) and complete omission of the argument.
    """

    def __call__(self, parser, namespace, values, option_string=None):  # noqa: D102 no docstring
        setattr(namespace, self.dest, values if values else Path("config/"))
        setattr(namespace, f"{self.dest}_explicit", True)


def prepare_parser():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="CMP test suite tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples of usage, assume the docker image is called `image`:

1. Default behavior (no additional arguments):
   docker run --rm -it ghcr.io/siemens/cmp-test
   Executes: robot --pythonpath=./ --outputdir=/report --include smoke scripts/smoke.robot tests/
   Does not require any configuration, runs the smoke test and any other test with the `smoke` tag.

2. Passing a minimal URL:
   docker run --rm -it ghcr.io/siemens/cmp-test --minimal http://example.com
   Executes: robot --pythonpath=./ --outputdir=/report --include minimal --variable SERVER_URL:http://example.com tests/
   Runs only tests tagged `minimal`, which only require the server's address and nothing else.

3. Using a custom configuration:
   docker run --rm -it ghcr.io/siemens/cmp-test -v ./reports:/report -v ./config:/config image --customconfig
   Runs all tests with the custom configuration given in a directory mounted to config/, will save reports to /reports.

4. Running Mock CA from a locally built container:
   docker build -t cmp-test -f data/dockerfiles/Dockerfile.tests .
   docker run --rm -it -p 5000:5000 cmp-test --mockca 5000
   Runs: python mock_ca/ca_handler.py --host 0.0.0.0 --port 5000

5. Running Mock CA from the remote container image:
   docker run --rm -it -p 5000:5000 ghcr.io/siemens/cmp-test --mockca 5000
   Runs: python mock_ca/ca_handler.py --host 0.0.0.0 --port 5000

6. Passing arbitrary arguments to robot (note the `--`):
   docker run --rm -it ghcr.io/siemens/cmp-test --minimal http://example.com -- --dryrun
   Runs: robot --pythonpath=./ --outputdir=/report --include minimal --variable SERVER_URL:http://example.com tests/ \
    --dryrun
""",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--smoke", action="store_true", help="Run smoke tests that don't require any configuration")
    group.add_argument("--minimal", help="Run tests that only need a CMP URL endpoint", type=valid_url, metavar="URL")
    group.add_argument(
        "--customconfig",
        help="Use custom configuration directory and run all tests",
        type=Path,
        nargs="?",
        default=Path("config/"),
        metavar="DIR",
        action=CustomConfigAction,
    )
    group.add_argument(
        "--mockca",
        type=int,
        metavar="PORT",
        help="Start the Mock CA server on the given port",
    )
    parser.add_argument("--tags", help="Run only tests with the given tags", type=str, nargs="+", default=[])
    parser.add_argument(
        "--ephemeral",
        help="Discard the detailed report generated by the test suite, the results printed on the screen are enough",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--verbose", help="Display additional debugging information", action="store_true", default=False
    )

    parser.add_argument(
        "robot_args", nargs=argparse.REMAINDER, help="Optional arguments to pass directlyto Robot Framework."
    )

    # Add a flag to track explicit usage of --customconfig, to differentiate between
    # when it was provided with a value, without a value, or not at all
    parser.set_defaults(customconfig_explicit=False)

    return parser


def verify_report_directory(ephemeral, smoke, verbose):
    """Check if the report directory exists and enforce some checks based on settings.

    Args:
        ephemeral (bool): If True, we don't care about potentially losing the detailed report.
        smoke (bool): If True, we only run smoke tests.
        verbose (bool): If True, additional information will be logged.

    """
    if os.path.exists("/report"):
        if verbose:
            log.info("Report will be saved to /report (inside your container)")
    else:
        if ephemeral or smoke:
            log.info(
                "Running in ephemeral mode, only brief results on screen, no file report. Consider running the "
                "container with `-v /path/on/host:/report` to ensure the report is saved."
            )
        else:
            log.warning(
                "The /report directory does not exist, the detailed test report will be lost after "
                "the container is removed. Run with --ephemeral to ignore this and only consider the "
                "results shown on stdout, or run the container with `-v /path/on/host:/report` to "
                "ensure the report is saved."
            )
            sys.exit(1)


def main():
    """Run the CMP test suite."""
    parser = prepare_parser()
    args = parser.parse_args()

    if args.verbose:
        log.debug(args)

    if args.mockca is not None:
        result = start_mock_ca(args.mockca, args.verbose)
        if result is None:
            sys.exit(1)
        return

    verify_report_directory(args.ephemeral, args.smoke, args.verbose)

    if args.robot_args:
        # One can pass additional arguments to RobotFramework by adding -- <robot args> at the end
        # of the command line, e.g. `docker run image --minimal http://example.com -- --dryrun`.
        # We prepare this piece here because we might need to add it later.
        additional_args = " " + " ".join(args.robot_args[1:])  # omit the "--" itself
    else:
        additional_args = ""

    if args.smoke:
        # Run the smoke test in scripts/smoke.robot, as well as any other test with the `smoke` tag
        command = "robot --pythonpath=./ --outputdir=/report --include smoke scripts/smoke.robot"
    elif args.minimal:
        # A minimal batch of tests that only need to know the server's address and nothing else, it is the easiest
        # way to get a taste of what the test suite can do while still doing some actual work with a real server.
        command = f"robot --pythonpath=./ --outputdir=/report --include minimal --variable CA_CMP_URL:{args.minimal}"

    elif args.customconfig_explicit:
        # The script was started with --customconfig, there are several possibilities:
        # [A] --customconfig without a specific path, so the default one is implied
        # [B] --customconfig with a specific path to a custom directory
        if args.customconfig == parser.get_default("customconfig"):
            # case [A], load the config from /config, where we expect it to be mounted when running within docker.
            config_path = Path("/config")
        else:
            # case [B], load the config from the path given by the user
            config_path = args.customconfig

        if not os.path.exists(config_path / "custom.robot"):
            config_guide = """It must be mounted to /config in the docker container (override with --customconfig)
and follow this structure:
/config
├── custom.robot   -  set the relevant variables, follow the examples given in config/ in the repo
├── data/          -  a directory with data files (keys, certificates, etc.) needed by your custom.robot"""
            log.warning("The configuration directory does not exist or is not structured correctly. %s", config_guide)
            sys.exit(1)

        # If we end up here, it means that the user took the time to set up a configuration directory and adjust
        # it to the specifics of their CMP server. We'll run all tests and rely on the given configuration and
        # data (e.g., certificates, keypairs, preshared passwords, etc.)
        if args.tags:
            included_tags = "--include " + " --include ".join(args.tags)
        else:
            included_tags = ""

        command = f"robot --pythonpath=./ --outputdir=/report --variable environment:custom {included_tags}"
    else:
        log.debug("No actionable command line arguments given, nothing to do")
        sys.exit(0)

    # Prepare the final command, appending additional arguments, if any, and ensuring that test/ is in
    # the end.
    command = f"{command} {additional_args} tests/"

    run_robot_command(command, args.verbose)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)5s - %(message)s")

    version = get_version()
    log.info("Starting CMP test suite v%s", version)
    main()
