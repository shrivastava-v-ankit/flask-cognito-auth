#!/usr/bin/env python3

"""
File handle the decorators for AWS Cognito login / logout features.
On successfull login, add "groups" in session object if user is
part of AWS Cognito group. This helps application for authorization.
"""

import logging
import json
import requests
from requests.auth import HTTPBasicAuth
from functools import wraps
from flask import redirect
from flask import request
from jose import jwt
from .config import Config
from flask import session
from flask import url_for


logger = logging.getLogger(__name__)
config = Config()


def login_handler(fn):
    """
    A decorator to redirect users to AWS Cognito login if they aren't already.
    If already logged in user will redirect redirect uri.
    Use this decorator on the login endpoint.
    This handle will not return to handle the respose rather redirect to
    redirect uri.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        aws_cognito_login = config.login_uri

        # https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
        res = redirect(aws_cognito_login)
        logger.info("Got Cognito Login, redirecting to AWS Cognito for Auth")
        return res
    return wrapper


def callback_handler(fn):
    """
    A decorator to handle redirects from AWS Cognito login and signup. It
    handles and verifies and exchangs the code for tokens.
    This decorator also pushes the basic informations in Flask session.
    Basic informations are:
        * username
        * group (List of Cognito groups if any)
        * id
        * email
        * expires
        * refresh_token
        * access_token
        * roles (List of AWS Cognito Assume roles)
        * All SAML assertions.
    Use this decorator on the redirect endpoint on your application.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_success = False
        logger.info("Login is successfull from AWS Cognito.")
        logger.info(
            "Authenticating AWS Cognito application / client, with code exchange.")

        csrf_token = config.state
        csrf_state = None

        if csrf_token:
            csrf_state = request.args.get('state')

        code = request.args.get('code')
        request_parameters = {'grant_type': 'authorization_code',
                              'client_id': config.client_id,
                              'code': code,
                              "redirect_uri": config.redirect_uri}
        response = requests.post(config.jwt_code_exchange_uri,
                                 data=request_parameters,
                                 auth=HTTPBasicAuth(config.client_id,
                                                    config.client_secret))

        # the response:
        # http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
        if response.status_code == requests.codes.ok:
            logger.info("Code exchange is successfull.")
            logger.info("Validating CSRF state exchange of AWS Cognito")

            if csrf_state == csrf_token:
                auth_success = True

                if csrf_token:
                    logger.info(
                        "CSRF state validation successfull. Login is successfull for AWS Cognito")

                logger.info("Decode the access token from response.")
                verify(response.json()["access_token"])
                id_token = verify(
                    response.json()["id_token"], response.json()["access_token"])

                username = None
                email = None
                provider_type = "cognito"
                if "identities" in id_token:
                    logger.info(
                        "Identities are present in authentication token. Will use that as priority.")

                    for identity in id_token['identities']:
                        if 'userId' in identity and not email:
                            email = identity['userId']
                        if "providerType" in identity and "cognito" in provider_type:
                            provider_type = identity["providerType"]

                        if 'primary' in identity and identity['primary']:
                            if 'userId' in identity:
                                email = identity['userId']
                            if "providerType" in identity:
                                provider_type = identity["providerType"]

                if not username:
                    username = id_token["cognito:username"]
                if not email and 'email' in id_token:
                    email = id_token["email"]

                groups = []
                if "cognito:groups" in id_token:
                    groups = id_token['cognito:groups']

                roles = []
                # Check if claim has preferred_role then set it.
                if 'cognito:preferred_role' in id_token:
                    roles.append(id_token['cognito:preferred_role'])

                # If preferred_role is not part of claim and list of
                # assume roles part of claim, then set it.
                if 'cognito:roles' in id_token and not roles:
                    roles = id_token['cognito:roles']

                skip_tokens = ["cognito:preferred_role",
                               "cognito:roles",
                               "cognito:username",
                               "cognito:groups",
                               "email",
                               "identities",
                               "at_hash",
                               "sub",
                               "email_verified",
                               "iss",
                               "nonce",
                               "aud",
                               "token_use",
                               "auth_time",
                               "iat",
                               "exp"]

                saml_assertions = []
                for token, val in id_token.items():
                    if token not in skip_tokens:
                        if isinstance(val, list):
                            vals = [str(item).strip() for item in val]
                        elif isinstance(val, str):
                            token_vals = val.replace("[", "")
                            token_vals = token_vals.replace("]", "")
                            token_vals = token_vals.split(",")
                            vals = [token_val.strip() for token_val in token_vals]
                        else:
                            vals = [str(val).strip()]
                
                        saml_assertions.append({token: vals})

                update_session(username=username,
                               id=id_token["sub"],
                               groups=groups,
                               email=email,
                               expires=id_token["exp"],
                               refresh_token=response.json()["refresh_token"],
                               access_token=response.json()["access_token"],
                               roles=roles,
                               provider_type=provider_type,
                               saml_assertions=saml_assertions)
        if not auth_success:
            error_uri = config.redirect_error_uri
            if error_uri:
                resp = redirect(url_for(error_uri))
                return resp
            else:
                msg = f"Something went wrong during authentication"
                return json.dumps({'Error': msg}), 500
        return fn(*args, **kwargs)
    return wrapper


def update_session(username: str,
                   id,
                   groups,
                   email: str,
                   expires,
                   refresh_token,
                   access_token,
                   roles,
                   provider_type,
                   saml_assertions):
    """
    Method to update the Flask Session object with the informations after
    successfull login.
    :param username (str):          AWS Cognito authenticated user.
    :param id (str):                ID of AWS Cognito authenticated user.
    :param groups (list):           List of AWS Cognito groups if authenticated
                                    user is subscribed.
    :param email (str):             AWS Cognito email if of authenticated user.
    :param expires (str):           AWS Cognito session timeout.
    :param refresh_token (str):     JWT refresh token received in respose.
    :param access_token (str):      JWT access token received in respose.
    :param roles (list):            List of AWS Assume roles.
    :param provider_type (str):     Default is "cognito". If authenticated
                                    using SAML provider then it will be "SAML"
    :param saml_assertions (list):  List of all SAML assertions.
    """
    session['username'] = username
    session['id'] = id
    session['groups'] = groups
    session['email'] = email
    session['expires'] = expires
    session['refresh_token'] = refresh_token
    session['access_token'] = access_token
    session['roles'] = roles
    session['provider_type'] = provider_type
    session['saml_assertions'] = saml_assertions
    session.modified = True


def verify(token: str, access_token: str = None):
    """
    Verifies a JWT string's signature and validates reserved claims.
    Get the key id from the header, locate it in the cognito keys and verify
    the key
    :param token (str):         A signed JWS to be verified.
    :param access_token (str):  An access token string. If the "at_hash" claim
                                is included in the
    :return id_token (dict):    The dict representation of the claims set,
                                assuming the signature is valid and all
                                requested data validation passes.
    """
    header = jwt.get_unverified_header(token)
    key = [k for k in config.jwt_cognito_key if k["kid"] == header['kid']][0]
    id_token = jwt.decode(token,
                          key,
                          audience=config.client_id,
                          access_token=access_token)
    return id_token


def logout_handler(fn):
    """
    A decorator to logout from AWS Cognito and return to signout uri.
    Use this decorator on the cognito logout endpoint.
    This handle will not return to handle any respose rather redirect to
    signout uri.
    This decorator also clears the basic informations from Flask session.
    Basic informations are:
        * username
        * group (List of Cognito groups if any)
        * id
        * email
        * expires
        * refresh_token
        * access_token
        * roles
        * provider_type
        * saml_assertions
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        update_session(username=None,
                       id=None,
                       groups=[],
                       email=None,
                       expires=None,
                       refresh_token=None,
                       access_token=None,
                       roles=[],
                       provider_type=None,
                       saml_assertions=[])
        logger.info(
            "AWS Cognito Login, redirecting to AWS Cognito for logout and terminating sessions")

        aws_cognito_logout = config.logout_uri

        # https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
        res = redirect(aws_cognito_logout)
        return res
    return wrapper
