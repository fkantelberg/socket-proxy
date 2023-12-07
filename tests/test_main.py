import argparse
from tempfile import NamedTemporaryFile
from unittest.mock import patch

import pytest

from socket_proxy import __main__ as main
from socket_proxy import base


def test_parser():
    assert isinstance(main.parse_args([]), argparse.Namespace)

    with patch("sys.exit", side_effect=[AssertionError]) as mock:
        with pytest.raises(AssertionError):
            main.parse_args(["-h"])

        mock.assert_called_once_with(0)

    with NamedTemporaryFile("w+") as fp:
        fp.write("[server]\nban_time=42")
        fp.flush()

        args = main.parse_args(["server", "--config", fp.name])
        assert args.ban_time == 42

        args = main.parse_args(["client", "--config", fp.name])
        assert args.ban_time == 60

    with NamedTemporaryFile("w+") as fp:
        fp.write("[servera]\nban_time=42")
        fp.flush()

        args = main.parse_args(["server", "--config", fp.name])
        assert args.ban_time == 60


@patch("socket_proxy.__main__.TunnelClient")
@patch("socket_proxy.__main__.GUIClient")
def test_run_client(gui_mock, tunnel_mock):
    with patch("sys.exit", side_effect=[AssertionError]) as mock:
        with pytest.raises(AssertionError):
            main.run_client(False)
        mock.assert_called_once_with(1)

    gui_mock.assert_not_called()
    tunnel_mock.assert_not_called()

    base.config.ca = True
    base.config.dst = "", 80
    base.config.connect = "", 2773

    main.run_client(True)
    gui_mock.assert_not_called()
    tunnel_mock.assert_called_once()
    tunnel_mock.return_value.start.assert_called_once()
    tunnel_mock.reset_mock()

    main.run_client(False)
    tunnel_mock.assert_not_called()
    gui_mock.assert_called_once()
    gui_mock.return_value.start.assert_called_once()
    gui_mock.reset_mock()


@patch("socket_proxy.__main__.ProxyServer")
def test_run_server(proxy_mock):
    with patch("sys.exit", side_effect=[AssertionError]) as mock:
        with pytest.raises(AssertionError):
            main.run_server()
        mock.assert_called_once_with(1)

    proxy_mock.assert_not_called()

    base.config.cert = True
    base.config.key = True

    main.run_server()
    proxy_mock.assert_called_once()
    proxy_mock.return_value.start.assert_called_once()


@patch("socket_proxy.__main__.run_client")
@patch("socket_proxy.__main__.run_server")
@patch("socket_proxy.__main__.parse_args", return_value=base.config)
@patch("socket_proxy.utils.configure_logging")
def test_main(log_mock, parse_mock, server_mock, client_mock):
    main.main(())

    log_mock.assert_called_once()
    parse_mock.assert_called_once()
    client_mock.assert_not_called()
    server_mock.assert_not_called()
    parse_mock.reset_mock()

    base.config.mode = "client"
    main.main(("client",))
    parse_mock.assert_called_once()
    server_mock.assert_not_called()
    client_mock.assert_called_once()
    client_mock.reset_mock()
    parse_mock.reset_mock()

    base.config.mode = "server"
    main.main(("server",))
    parse_mock.assert_called_once()
    client_mock.assert_not_called()
    server_mock.assert_called_once()
    server_mock.reset_mock()

    server_mock.side_effect = [KeyboardInterrupt]
    main.main(())
