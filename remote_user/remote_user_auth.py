
import os
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode, Bool


class RemoteUserLoginHandler(BaseHandler):

    def get(self):
        header_name = self.authenticator.header_name
        remote_user = self.request.headers.get(header_name, "")
        user_suffix = self.authenticator.user_suffix
        remove_user_suffix = self.authenticator.remove_user_suffix

        if len(remote_user) <= len(user_suffix) \
           or not remote_user.endswith(user_suffix):
            raise web.HTTPError(401)
        else:
            if remove_user_suffix and not user_suffix == '':
                remote_user = remote_user[:-len(user_suffix)]

            user = self.user_from_username(remote_user)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))


class RemoteUserAuthenticator(Authenticator):
    """
    Accept the authenticated user name from the REMOTE_USER HTTP header.
    """
    header_name = Unicode(
        default_value='REMOTE_USER',
        config=True,
        help="""HTTP header to inspect for the authenticated username.""")

    user_suffix = Unicode(
        default_value='',
        config=True,
        help="""Ensure that all usernames have this suffix.""")

    remove_user_suffix = Bool(
        default_value=False,
        config=True,
        help="""Should the user_suffix be removed.""")

    def get_handlers(self, app):
        return [
            (r'/login', RemoteUserLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()


class RemoteUserLocalAuthenticator(LocalAuthenticator):
    """
    Accept the authenticated user name from the REMOTE_USER HTTP header.
    Derived from LocalAuthenticator for use of features such as adding
    local accounts through the admin interface.
    """
    header_name = Unicode(
        default_value='REMOTE_USER',
        config=True,
        help="""HTTP header to inspect for the authenticated username.""")

    user_suffix = Unicode(
        default_value='',
        config=True,
        help="""Ensure that all usernames have this suffix.""")

    remove_user_suffix = Bool(
        default_value=False,
        config=True,
        help="""Should the user_suffix be removed.""")

    def get_handlers(self, app):
        return [
            (r'/login', RemoteUserLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()
