import nox


@nox.session()
def clean(session):
    session.install("coverage")
    session.run("coverage", "erase")


@nox.session()
def py3(session):
    session.install(
        "pytest",
        "pytest-asyncio",
        "pytest-cov",
        "pytest-timeout",
        "pytest-xdist",
        "aiohttp",
        "coverage",
    )
    session.run(
        "pytest",
        "--cov=src/socket_proxy",
        "--cov-append",
        "-n=4",
        "--asyncio-mode=auto",
        "--timeout=5",
    )


@nox.session()
def report(session):
    session.install("coverage")
    session.run("coverage", "html")
    session.run("coverage", "report", "--fail-under=80")
