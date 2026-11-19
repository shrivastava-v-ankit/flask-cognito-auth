
from flask_cognito_auth.config import Config
from flask_cognito_auth.decorators import update_session, parse_saml_assertions
from .server import app
from .server import app_exception
from .server import app_lazy
import pytest
from flask import Flask
from flask import session
from datetime import datetime


def test_cognito_config(app):
    with app.test_request_context():
        config = Config()

        app.config['COGNITO_REGION'] = "us-east-1"
        app.config['COGNITO_USER_POOL_ID'] = "us-east-1_myPoolId"
        app.config['COGNITO_CLIENT_ID'] = "123drfthinvdr57opQWerv56"
        app.config['COGNITO_CLIENT_SECRET'] = "mysupersecretclientid"
        app.config['COGNITO_REDIRECT_URI'] = "http://localhost:5000/cognito/callback"
        app.config['COGNITO_SIGNOUT_URI'] = "http://localhost:5000/login"
        app.config['ERROR_REDIRECT_URI'] = "page500"

        auth_mgr = config.get_auth_manager
        auth_mgr.jwt_key = "mypublickkey"

        assert config.region == "us-east-1"
        assert config.user_pool_id == "us-east-1_myPoolId"
        assert config.client_id == "123drfthinvdr57opQWerv56"
        assert config.redirect_uri == "http://localhost:5000/cognito/callback"
        assert config.redirect_error_uri == "page500"
        assert config.client_secret == "mysupersecretclientid"
        assert config.signout_uri == "http://localhost:5000/login"
        assert auth_mgr.jwt_key == config.jwt_cognito_key
        assert config.exempt_methods == ['OPTIONS']

        app.config['COGNITO_DOMAIN'] = "https://mycognitodomain.com"
        assert config.domain == "https://mycognitodomain.com"

        app.config['COGNITO_DOMAIN'] = "mycognitodomain.com"
        assert config.domain == "https://mycognitodomain.com"

        assert config.login_uri == (
            f"https://mycognitodomain.com/authorize"
            f"?client_id=123drfthinvdr57opQWerv56"
            f"&response_type=code"
            "&redirect_uri=http://localhost:5000/cognito/callback"
        )

        app.config['COGNITO_STATE'] = "mystate"
        assert config.login_uri == (
            f"https://mycognitodomain.com/authorize"
            f"?client_id=123drfthinvdr57opQWerv56"
            f"&response_type=code&state={config.state}"
            "&redirect_uri=http://localhost:5000/cognito/callback"
        )

        assert config.logout_uri == (
            f"https://mycognitodomain.com/logout?response_type=code"
            f"&client_id=123drfthinvdr57opQWerv56"
            f"&logout_uri=http://localhost:5000/login"
        )

        assert config.issuer == (
            "https://cognito-idp.us-east-1.amazonaws.com/"
            "us-east-1_myPoolId"
        )
        assert config.public_key_uri == (
            "https://cognito-idp.us-east-1.amazonaws.com/"
            "us-east-1_myPoolId/.well-known/jwks.json"
        )
        assert config.jwt_code_exchange_uri == (
            "https://mycognitodomain.com/oauth2/token"
        )


def test_cognito_auth_exeption(app_exception):
    with app_exception.test_request_context():
        config = Config()

        try:
            _ = config.get_auth_manager
        except RuntimeError as e:
            assert str(
                e
            ) == "Flask Cognito Auth extention is not registerd with Flask application."

        try:
            app_exception.config['COGNITO_REGION'] = ""
            _ = config.region
        except RuntimeError as e:
            assert str(e) == "COGNITO_REGION must be specified."

        try:
            _ = config.user_pool_id
        except RuntimeError as e:
            assert str(
                e
            ) == "COGNITO_USER_POOL_ID must be specified to locate the auth url."


def test_cognito_auth_lazy(app_lazy):
    with app_lazy.test_request_context():
        config = Config()
        app_lazy.config['COGNITO_REGION'] = "us-east-1"

        assert config.region == "us-east-1"


def test_cognito_session(app):
    with app.test_request_context():
        datetime_now = datetime.now()

        update_session(
            username="myusername",
            id="myuserid",
            groups=['mygroup1', 'mygroup2'],
            email='myemail@domain.com',
            expires=datetime_now,
            refresh_token="mysupersecretrefreshtoken",
            access_token="mysupersecretaccesstoken",
            roles=["assumerole1", "assumerole2"],
            provider_type="SAML",
            saml_assertions=[{"profile": ["g1", "g2"]}]
        )

        assert session['username'] == "myusername"
        assert session['id'] == "myuserid"
        assert session['groups'] == ['mygroup1', 'mygroup2']
        assert session['email'] == "myemail@domain.com"
        assert session['expires'] == datetime_now
        assert session['refresh_token'] == "mysupersecretrefreshtoken"
        assert session['access_token'] == "mysupersecretaccesstoken"
        assert session['roles'] == ["assumerole1", "assumerole2"]
        assert session['roles'] == ["assumerole1", "assumerole2"]
        assert session['provider_type'] == "SAML"
        assert session['saml_assertions'] == [{"profile": ["g1", "g2"]}]


# ------------------------------------------------------------
# Regression tests for JWT claim processing
# ------------------------------------------------------------

def test_cognito_list_valued_claim():
    """List-valued claims such as amr must be supported."""
    id_token = {
        "amr": ["pwd", "mfa"]
    }

    result = parse_saml_assertions(id_token, [])

    assert result == [
        {"amr": ["pwd", "mfa"]}
    ]


def test_cognito_string_valued_claim():
    """String-valued claims retain existing behavior."""
    id_token = {
        "custom:roles": "admin, developer"
    }

    result = parse_saml_assertions(id_token, [])

    assert result == [
        {"custom:roles": ["admin", "developer"]}
    ]


def test_cognito_skip_tokens():
    """Excluded JWT claims must not appear in assertions."""
    id_token = {
        "sub": "123456",
        "amr": ["pwd"]
    }

    result = parse_saml_assertions(
        id_token,
        ["sub"]
    )

    assert result == [
        {"amr": ["pwd"]}
    ]


def test_cognito_mixed_claim_types():
    """String and list-valued claims can coexist."""
    id_token = {
        "amr": ["pwd", "mfa"],
        "custom:department": "engineering"
    }

    result = parse_saml_assertions(id_token, [])

    assert result == [
        {"amr": ["pwd", "mfa"]},
        {"custom:department": ["engineering"]}
    ]


def test_cognito_single_item_list():
    """A list containing one element remains a list."""
    id_token = {
        "amr": ["pwd"]
    }

    result = parse_saml_assertions(id_token, [])

    assert result == [
        {"amr": ["pwd"]}
    ]


def test_cognito_empty_list():
    """Empty list-valued claims should not raise errors."""
    id_token = {
        "amr": []
    }

    result = parse_saml_assertions(id_token, [])

    assert result == [
        {"amr": []}
    ]


def test_cognito_numeric_claim():
    """Numeric claims should be converted to strings."""
    id_token = {
        "custom:level": 5
    }

    result = parse_saml_assertions(id_token, [])

    assert result == [
        {"custom:level": ["5"]}
    ]


def test_cognito_empty_claims():
    """An empty token dictionary produces no assertions."""
    result = parse_saml_assertions({}, [])

    assert result == []
