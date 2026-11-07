"""``[network]``: the service's optional network API listener (ADR-051, server-native approach).

Absent by default (no listener at all). Every TCP address speaks TLS unless it is loopback and the
owner opted into plain HTTP behind a same-host proxy; addresses are IP literals; the table holds
paths, never a key; and FinishUP's own config writers keep the table.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import cast

import pytest

from finishup.config.load import load_config, validate_config_mapping
from finishup.config.models import ConfigError, FinishUpConfig, parse_listen_address
from finishup.config.write import render_config_toml, write_config_toml
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import validate_schema_instance


def _network(table: dict[str, object]) -> FinishUpConfig:
    return validate_config_mapping({"network": table})


def test_no_network_table_means_no_listener() -> None:
    config = validate_config_mapping({})
    assert config.network is None
    assert "[network]" not in render_config_toml(config)


def test_a_tls_listener_and_the_api_socket() -> None:
    config = _network(
        {
            "listen": ["127.0.0.1:8443", "[::1]:8443", "0.0.0.0:9443"],
            "tls_cert": "/etc/finishup/cert.pem",
            "tls_key": "/etc/finishup/key.pem",
            "api_socket": True,
        }
    )
    network = config.network
    assert network is not None
    assert network.listen == ("127.0.0.1:8443", "[::1]:8443", "0.0.0.0:9443")
    assert [address.loopback for address in network.listen_addresses] == [True, True, False]
    assert network.api_socket and not network.allow_plain_loopback


def test_plain_http_only_on_loopback_with_the_opt_in() -> None:
    plain = _network({"listen": ["127.0.0.1:8080"], "allow_plain_loopback": True})
    assert plain.network is not None and plain.network.tls_cert is None
    tables: tuple[dict[str, object], ...] = (
        {"listen": ["127.0.0.1:8080"]},
        {"listen": ["192.168.1.10:8080"], "allow_plain_loopback": True},
        {"listen": ["0.0.0.0:8080"], "allow_plain_loopback": True},
    )
    for table in tables:
        with pytest.raises(ConfigError) as raised:
            _network(table)
        assert raised.value.reason_code == "network_tls_required"


def test_only_the_api_socket_needs_no_tls() -> None:
    config = _network({"api_socket": True})
    assert config.network is not None and config.network.listen == ()


@pytest.mark.parametrize(
    ("table", "reason"),
    [
        ({}, "network_listener_missing"),
        ({"listen": ["localhost:8443"], "api_socket": True}, "network_listen_invalid"),
        ({"listen": ["127.0.0.1"], "api_socket": True}, "network_listen_invalid"),
        ({"listen": ["127.0.0.1:0"], "api_socket": True}, "network_listen_invalid"),
        ({"listen": ["::1:8443"], "api_socket": True}, "network_listen_invalid"),
        ({"listen": "127.0.0.1:8443", "api_socket": True}, "network_listen_invalid"),
        (
            {"listen": ["127.0.0.1:8443", "127.0.0.1:8443"], "tls_cert": "/c", "tls_key": "/k"},
            "network_listen_invalid",
        ),
        ({"api_socket": True, "tls_cert": "/c"}, "network_tls_invalid"),
        ({"api_socket": True, "tls_cert": "c.pem", "tls_key": "k.pem"}, "network_tls_invalid"),
        ({"api_socket": "yes"}, "config_value_invalid"),
        ({"api_socket": True, "port": 1}, "unknown_config_key"),
        ({"api_socket": True, "api_token": "x"}, "secret_in_config"),
    ],
)
def test_bad_tables_are_refused_with_closed_reasons(table: dict[str, object], reason: str) -> None:
    with pytest.raises(ConfigError) as raised:
        _network(table)
    assert raised.value.reason_code == reason


def test_listen_addresses_are_canonical_ip_literals() -> None:
    assert parse_listen_address("[0:0:0:0:0:0:0:1]:443").text() == "[::1]:443"
    assert parse_listen_address("10.0.0.1:65535").port == 65_535
    with pytest.raises(ConfigError):
        parse_listen_address("224.0.0.1:443")


def test_config_writers_keep_the_table_and_it_matches_the_schema(tmp_path: Path) -> None:
    config = _network(
        {
            "listen": ["127.0.0.1:8443"],
            "tls_cert": "/etc/finishup/cert.pem",
            "tls_key": "/etc/finishup/key.pem",
            "api_socket": True,
        }
    )
    rendered = render_config_toml(config)
    assert '[network]\nlisten = ["127.0.0.1:8443"]\napi_socket = true\n' in rendered
    validate_schema_instance("yoetz-config", "1.4.0", cast(JsonValue, tomllib.loads(rendered)))
    path = write_config_toml(config, path=tmp_path / "config.toml")
    assert load_config({}, {}, path) == config
