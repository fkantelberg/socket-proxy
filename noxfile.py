import nox


@nox.session()
def clean(session):
    session.install("coverage[toml]")
    session.run("coverage", "erase")


@nox.session()
def py3(session):
    session.install(
        "-e",
        ".",
        "pytest",
        "pytest-asyncio",
        "pytest-cov",
        "pytest-timeout",
        "pytest-xdist",
        "aiohttp",
        "coverage[toml]",
        "typing_extensions",
    )
    session.run("./certs.sh", "client", external=True)
    session.run("./certs.sh", "server", external=True)
    session.run(
        "pytest",
        "--cov=src/socket_proxy",
        "--cov-append",
        "-n=4",
    )


@nox.session()
def report(session):
    session.install("coverage[toml]")
    session.run("coverage", "html")
    session.run("coverage", "report", "--fail-under=80")
