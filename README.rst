roughrider.cors
***************

This package allows you to create a policy that can handle CORS.
It can be used with any python framework as it's totally agnostic.
It can cook response headers, even for preflight requests.


Example
=======

.. code-block:: python

  from roughrider.cors.policy import CORSPolicy

  cors = CORSPolicy(
      methods=['GET', 'POST'],
      allow_headers=['Accept-Encoding'],
      expose_headers=['Accept-Encoding'],
      max_age=19000
  )

  headers = list(cors.headers())

  # Arguments for the preflight should be extracted from the request.
  # depending on the type of framework you use (WSGI, ASGI...)
  preflight_headers = list(cors.preflight(
      origin='http://example.com',
      acr_headers='X-Custom-Header, Accept-Encoding'
  ))
