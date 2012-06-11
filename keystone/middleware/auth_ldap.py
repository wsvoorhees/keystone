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
LDAP AUTH MIDDLEWARE

This WSGI component authenticates incoming requests against the specified ldap server.

This is an Auth component as per: http://wiki.openstack.org/openstack-authn

"""

import os
import logging
from webob.exc import Request, Response
from webob.exc import HTTPUnauthorized
from keystone.common import wsgi
from keystone import config


import ldap
#LDAP Constants
LDAP_SUCCESS_CODE = 97 #LDAP protocol defines messsage 97 as success
PROTOCOL_NAME = "LDAP Authentication"
CONTEXT_ENV = 'openstack.context'
PARAMS_ENV = 'openstack.params'

AUTH_FAIL = 1
AUTH_FAIL_EXISTS = 2 #authentication failed, but the user we where trying to authenticate against exited.
AUTH_SUCCESS = 0



logger = logging.getLogger(__name__)  # pylint: disable=C0103

CONF = {'delay_auth_decision':True, 
        'disable_fallthrough':False,
        'anonymous_dn':'cn=anonymous,dc=nic,dc=uoregon,dc=edu',
        'anonymous_pw':
        'auth_dn':
        'ldap_conn_str':
        }



class AuthLDAP(wsgi.Middleware):
    """Auth Middleware that handles authenticating client calls
       Should be called after JsonBodyMiddleware
    """
    
    @classmethod
    def factory(cls, global_config, **local_config):
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, conf)
        return _factory


    def __init__(self, app_from_paste, config):
        """ This enables kwarg authentication"""
        config['delay_auth_decision'] = (config['delay_auth_decision'] == 'True') #Quick and Dirty convert string to bool
        config['disable_fallthrough'] = (config['disable_fallthrough'] == 'True') #Quick and Dirty convert string to bool
        self.CONF= config
        self.application = app_from_paste

    def _decorate_request(self, index, value, request_headers, context):
        """Add headers to request and context
        Adding to headers is to support future compliance with the middleware layer 
        as definied by the middleware_architecture document.
        Adding to context is to support my patches to the keystone.service.TokenController.authenticate 
        method.
        """
        context[index] = value
        request_headers['HTTP_%s' % index] = value


    def process_request(self, req):
        params = req.environ.get(PARAMS_ENV, {})
        context = req.environ.get(CONTEXT_ENV, {})
        # make sure we have no unicode keys for py2.6.
        params = self._normalize_dict(params)

        #This context data should exist because of the  JsonBodyMiddleware
        auth_hash = params.get('auth', None)
        if auth_hash:
            creds = auth_hash.get('passwordCredentials', None)
            if creds:
                validate_result = self.validate_creds(creds.get('username', None), creds.get('password', None))
                logger.debug("validate_request is " + str(validate_result))
                if validate_result:
                    #Claims were rejected
                    if not self.CONF.get('delay_auth_decision', None):
                        # Reject request (or ask for valid claims)
                        return HTTPUnauthorized("LDAP Authentication required",
                            [('WWW-Authenticate',
                              'Basic realm= "LDAP Realm"')])
                    else:
                        # Authentication should be forwarded.
                        if(validate_result == AUTH_FAIL):
                            self._decorate_request("X_IDENTITY_STATUS", "Indeterminate", req.headers, context)
                            
                        elif(self.CONF.get('disable_fallthrough', False) and (validate_result == AUTH_FAIL_EXISTS)): #Do not forward request if the user was found int he LDAP layer.
                            return HTTPUnauthorized("LDAP Authentication required", [('WWW-Authenticate', 'Basic realm= "LDAP Realm"')])
                elif validate_result == AUTH_SUCCESS:
                    #claims are valid.
                    self._decorate_request('X_AUTHORIZATION', "Proxy %s" % creds['username'], req.headers, context)
                    self._decorate_request('X_IDENTITY_STATUS', "Confirmed", req.headers, context)
                    self._decorate_request('X_TENANT', 'blank', req.headers, context)

        req.environ[CONTEXT_ENV] = context

    def validate_creds(self, username, password):
        uid_string = "uid=" + username
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        try:
            #conn = ldap.initialize('ldap://172.17.202.25')
            conn = ldap.initialize(self.CONF['ldap_conn_str'])
            conn.simple_bind_s(self.CONF['anonymous_dn'], self.CONF['anonymous_pw']) 
            logger.debug("Anonymous bind succeeded")
        except ldap.LDAPError, e:
            logger.error("Problem performing the Anonymous bind")
            logger.error(e)
            return AUTH_FAIL

        try:
            search_result = conn.search_s(self.CONF['auth_dn'], ldap.SCOPE_SUBTREE, uid_string)
        except ldap.LDAPError, e:
            logger.error("Error searching for user %s on ldap server" % username)
            logger.error(e)
            return AUTH_FAIL

        if(not search_result): 
            logger.debug("user %s was not found on ldap server" % username)
            return AUTH_FAIL
        try:
            auth_result = conn.simple_bind_s(",".join([uid_string, self.CONF['auth_dn']]), password)
            if(auth_result[0] == LDAP_SUCCESS_CODE):
                logger.debug("user %s authenticated!" % username)
                return AUTH_SUCCESS
        except ldap.LDAPError, e:
            logger.error(e)
        return AUTH_FAIL_EXISTS #Unless we hit the true statement at the end of  this function we return false.

