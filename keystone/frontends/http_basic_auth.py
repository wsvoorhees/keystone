#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
HTTP basic Auth to keystone auth.

This WSGI component
- transforms an authentication request formulated as an HTTP Basic Auth
as defined by RFC2617 - http://tools.ietf.org/html/rfc2617
and makes an authentication call on keystone in the native keystone 2.0 API.
"""

import ast
import json
import logging
from webob.exc import Request

import keystone.utils as utils

PROTOCOL_NAME = "HTTP Basic Authentication"

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class HTTPBasicProtocol(object):
    """HTTP Basic Middleware that handles authenticating client calls"""

    def __init__(self, app, conf):
        """ Common initialization code """
        msg = _("Starting the %s component" % PROTOCOL_NAME)
        logger.info(msg)
        self.conf = conf
        self.app = app

    # Handle 1.0 and 1.1 calls via middleware.
    # Right now I am treating every call of 1.0 and 1.1 as call
    # to authenticate
    def __call__(self, env, start_response):
        """ Handle incoming request. Transform. And send downstream. """
        logger.debug("Entering .__call__")
        request = Request(env)

        #Look for authentication
        if 'HTTP_AUTHORIZATION' not in env:
            #forward response
            return ret(env, start_response)
        else:
            # Claims were provided - validate them
            import base64
            auth_header = env['HTTP_AUTHORIZATION']
            _auth_type, encoded_creds = auth_header.split(None, 1)
            user, password = base64.b64decode(encoded_creds).split(':', 1)

            params = {"auth": {"passwordCredentials":
                {"username": user,
                    "password": password}}}

            import json
            request.body = json.dumps(params)
            #Make request to keystone
            logger.debug("Not a v1.0/v1.1 call, so passing downstream")
            return self.app(env, start_response)

        def forward_request(self, env, start_response):
            if self.app:
                return self.app(env, start_response)

def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        """Closure to return"""
        return HTTPBasicProtocol(app, conf)
    return auth_filter
