import pytest
from roughrider.cors.policy import CORSPolicy


def test_policy():
    cors1 = CORSPolicy()
    cors2 = CORSPolicy()
    assert cors1 == cors2
    assert not cors1 is cors2

    cors1 = CORSPolicy(
        methods=['GET', 'POST'],
        allow_headers=['Accept-Encoding'],
        expose_headers=['Accept-Encoding'],
        max_age=36000
    )
    assert cors1 != cors2

    cors2 = CORSPolicy(
        methods=['GET', 'POST'],
        allow_headers=['Accept-Encoding'],
        expose_headers=['Accept-Encoding'],
        max_age=36000
    )
    assert cors1 == cors2

    cors2 = CORSPolicy(
        methods=['GET', 'POST'],
        allow_headers=['Accept-Encoding'],
        expose_headers=['Accept-Encoding'],
        max_age=19000
    )
    assert cors1 != cors2

    cors2 = CORSPolicy(
        methods=['GET', 'POST'],
        allow_headers=[],
        expose_headers=['Accept-Encoding'],
        max_age=36000
    )
    assert cors1 != cors2


def test_empty_policy():

    cors = CORSPolicy()
    assert cors.origin == '*'
    assert cors.methods is None
    assert cors.allow_headers is None
    assert cors.expose_headers is None
    assert cors.credentials is None
    assert cors.max_age is None

    with pytest.raises(AttributeError):
        cors.origin = 'new origin'

    assert list(cors.headers()) == [
        ('Access-Control-Allow-Origin', '*')
    ]


def test_policy_headers():
    cors = CORSPolicy(
        allow_headers=['X-Custom-Header', 'Accept-Encoding'],
    )
    assert cors.allow_headers == ['X-Custom-Header', 'Accept-Encoding']
    assert list(cors.headers()) == [
        ('Access-Control-Allow-Origin', '*'),
        ('Access-Control-Allow-Headers', 'X-Custom-Header, Accept-Encoding')
    ]

    cors = CORSPolicy(
        allow_headers=['X-Custom-Header', 'Accept-Encoding'],
        expose_headers=['Content-Type'],
    )
    assert cors.allow_headers == ['X-Custom-Header', 'Accept-Encoding']
    assert cors.expose_headers == ['Content-Type']
    assert list(cors.headers()) == [
        ('Access-Control-Allow-Origin', '*'),
        ('Access-Control-Allow-Headers', 'X-Custom-Header, Accept-Encoding'),
        ('Access-Control-Expose-Headers', 'Content-Type'),
    ]


def test_policy_methods():
    cors = CORSPolicy(
        methods=['GET', 'POST'],
    )
    assert cors.methods == ['GET', 'POST']
    assert list(cors.headers()) == [
        ('Access-Control-Allow-Origin', '*'),
        ('Access-Control-Allow-Methods', 'GET, POST')
    ]


def test_policy_origin():
    cors = CORSPolicy(
        origin='http://example.com'
    )
    assert cors.origin == 'http://example.com'
    assert list(cors.headers()) == [
        ('Access-Control-Allow-Origin', 'http://example.com'),
    ]


def test_policy_max_age():
    cors = CORSPolicy(
        max_age=36000
    )
    assert cors.max_age == 36000
    assert list(cors.headers()) == [
        ('Access-Control-Allow-Origin', '*'),
        ('Access-Control-Max-Age', '36000')
    ]


def test_policy_credentials():
    cors = CORSPolicy(
        credentials=True
    )
    assert cors.credentials is True
    assert list(cors.headers()) == [
        ('Access-Control-Allow-Origin', '*'),
        ('Access-Control-Allow-Credentials', 'true'),
    ]
