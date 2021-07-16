SafeList
********

A CORS-safelisted request header is one of the following HTTP headers:

  - Accept,
  - Accept-Language,
  - Content-Language,
  - Content-Type.


Additional restrictions
=======================

CORS-safelisted headers must also fulfill the following requirements in order to be a CORS-safelisted request header:

  - For Accept-Language and Content-Language: can only have values consisting of 0-9, A-Z, a-z, space or *,-.;=.

  - For Accept and Content-Type: can't contain a CORS-unsafe request header byte: 0x00-0x1F (except for 0x09 (HT), which is allowed), "():<>?@[\]{}, and 0x7F (DEL).

  - For Content-Type: needs to have a MIME type of its parsed value (ignoring parameters) of either application/x-www-form-urlencoded, multipart/form-data, or text/plain.

  - For any header: the value’s length can't be greater than 128.
