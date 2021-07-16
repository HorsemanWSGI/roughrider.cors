from typing import Optional, Set, NamedTuple, Literal, Tuple, Iterator


Header = Tuple[str, str]
Headers = Iterator[Header]
HTTPVerb = Literal[
    "GET", "HEAD", "PUT", "DELETE", "PATCH", "POST", "OPTIONS"]


class CORSPolicy(NamedTuple):
    origin: str = "*"
    methods: Optional[Set[HTTPVerb]] = None
    allow_headers: Optional[Set[str]] = None
    expose_headers: Optional[Set[str]] = None
    credentials: Optional[bool] = None
    max_age: Optional[int] = None

    def headers(self) -> Headers:
        yield "Access-Control-Allow-Origin", self.origin
        if self.methods:
            values = ", ".join(self.methods)
            yield "Access-Control-Allow-Methods", values
        if self.allow_headers:
            values = ", ".join(self.allow_headers)
            yield "Access-Control-Allow-Headers", values
        if self.expose_headers:
            values = ", ".join(self.expose_headers)
            yield "Access-Control-Expose-Headers", values
        if self.credentials:
            yield "Access-Control-Allow-Credentials", "true"
        if self.max_age:
            yield "Access-Control-Max-Age", str(self.max_age)

    def preflight(self, environ) -> Headers:
        if origin := environ.get("HTTP_ORIGIN"):
            if self.origin == '*':
                yield "Access-Control-Allow-Origin", '*'
            elif origin == self.origin:
                yield "Access-Control-Allow-Origin", origin
                yield "Vary", "Origin"

        if not self.methods:
            if method := environ.get("HTTP_ACCESS_CONTROL_REQUEST_METHOD"):
                yield "Access-Control-Allow-Methods", method
        else:
            yield "Access-Control-Allow-Methods", ", ".join(self.methods)

        if self.allow_headers:
            values = ", ".join(self.allow_headers)
            yield "Access-Control-Allow-Headers", values
        elif self.expose_headers:
            values = ", ".join(self.expose_headers)
            yield "Access-Control-Expose-Headers", values
        elif acrh := environ.get("HTTP_ACCESS_CONTROL_REQUEST_HEADERS"):
            yield "Access-Control-Allow-Methods", acrh
