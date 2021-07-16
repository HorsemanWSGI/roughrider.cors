import pytest
from roughrider.cors.policy import CORSPolicy


def test_policy_headers_preflight():

    cors = CORSPolicy()
    assert list(cors.preflight(
        acr_headers='X-Custom-Header, Accept-Encoding'
    )) == [
        ('Access-Control-Allow-Headers', 'X-Custom-Header, Accept-Encoding')
    ]

    cors = CORSPolicy(
        allow_headers=['X-Custom-Header']
    )
    assert list(cors.preflight(
        acr_headers='X-Custom-Header, Accept-Encoding'
    )) == [
        ('Access-Control-Allow-Headers', 'X-Custom-Header')
    ]

    cors = CORSPolicy(
        allow_headers=['X-Custom-Header', 'Accept-Encoding'],
        expose_headers=['Accept-Encoding']
    )
    assert list(cors.preflight(
        acr_headers='X-Custom-Header, Accept-Encoding'
    )) == [
        ('Access-Control-Allow-Headers', 'X-Custom-Header, Accept-Encoding'),
        ('Access-Control-Expose-Headers', 'Accept-Encoding')
    ]

    cors = CORSPolicy(
        expose_headers=['Accept-Encoding']
    )
    assert list(cors.preflight(
        acr_headers='X-Custom-Header, Accept-Encoding'
    )) == [
        ('Access-Control-Allow-Headers', 'X-Custom-Header, Accept-Encoding'),
        ('Access-Control-Expose-Headers', 'Accept-Encoding')
    ]


def test_policy_method_preflight():

    cors = CORSPolicy()
    assert list(cors.preflight(
        acr_method='POST'
    )) == [
        ('Access-Control-Allow-Methods', 'POST')
    ]

    cors = CORSPolicy(methods=['GET', 'POST'])
    assert list(cors.preflight(
        acr_method='POST'
    )) == [
        ('Access-Control-Allow-Methods', 'GET, POST')
    ]


def test_policy_origin_preflight():

    cors = CORSPolicy()
    assert list(cors.preflight()) == []
    assert list(cors.preflight(
        origin='*'
    )) == [
        ('Access-Control-Allow-Origin', '*')
    ]

    cors = CORSPolicy(origin='http://example.com')
    assert list(cors.preflight(
        origin='*'
    )) == [
        ('Access-Control-Allow-Origin', 'http://example.com'),
        ('Vary', 'Origin')
    ]

    assert list(cors.preflight(
        origin='http://example.com'
    )) == [
        ('Access-Control-Allow-Origin', 'http://example.com'),
        ('Vary', 'Origin')
    ]
