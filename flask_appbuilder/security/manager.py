import datetime
import logging
from flask import url_for,g,session
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager,current_user
from flask_openid import OpenID
from flask_babel import lazy_gettext as _
from .views import AuthDBView,AuthOIDView,ResetMyPasswordView,AuthLDAPView,AuthOAuthView,AuthRemoteUserView,ResetPasswordView,UserDBModelView,UserLDAPModelView,UserOIDModelView,UserOAuthModelView,UserRemoteUserModelView,RoleMOdelView,PermissionViewModelView,ViewMenuModelView,PermissionModelView,UserStatsChartView,RegisterUserModelView,UserInfoEditView
from .registerviews import RegisterUserDBView,RegisterUserOIDView,RegisterUserOAuthView
from ..basemanager import BaseManager
from ..const import AUTH_OID,AUTH_DB,AUTH_LDAP,AUTH_REMOTE_USER,AUTH_OAUTH,\
        LOGMSG_ERR_SEC_AUTH_LDAP,LOGMSG_WAR_SEC_NO_USER,\
        LOGMSG_WAR_SEC_NOLDAP_OBJ,LOGMSG_WAR_SEC_LOGIN_FAILED


log = logging.getLogger(__name__)


class AbstractSecurityManager(BaseManager):
    """
        Abstract SecurityManager class.declares all methods used by the framework.
        There is no assuptions about security models or auth types.
    """
    def add_permissions_view(self,base_permissions,view_menu):

        raise NotImplementdError

    def add_permissions_menu(self,view_menu_name):
        raise NotImplementdError

    def register_views(self):
        raise NotImplementdError

    def is_item_public(self,permission_name,view_name):
        raise NotImplementdError

    def has_access(self,permission_name,view_name):
        raise NotImplementdError

    def security_cleanup(self,baseviews,menus):
        raise NotImplementdError


def _oauth_tokengetter(token=None):
    token = session.get('oauth')
    log.debug("Token Get:{0}".format(token))
    return token


class BaseSecurityManager(AbstractSecurityManager):
    auth_view = None
    user_view = None
    registeruser_view = None
    lm = None
    """Flask-Login LoginManager"""
    oid = None
    """ Flask-OPenID OpenID"""
    oauth = None
    oauth_remotes = None
    oauth_tokengetter = _oauth_tokengetter
    oauth_user_info = None

    user_model = None
    role_model = None
    permission_model = None
    viewmenu_model = None
    permissionview_model = None
    registeruser_model = None

    userdbmodelview = UserDBModelView
    userldapmodelview = UserLDAPModelView
    useroidmodelview = UserOIDModelView
    useroauthmodelview = UserOAuthModelView
    userremoteusermodelview = UserRemoteUserModelView
    registerusermodelview = RegisterUserModelView

    authdbview = AuthDBView
    authldapview = AuthLDAPView
    authoidview = AuthOIDView
    authoauthview = AuthOAuthView
    authremoteuserview = AuthRemoteUserView

    registeruserdbview = RegisterUserDBView
    registeruseroidview = RegisterUserOIDView
    registeruseroauthview = RegisterUserOAuthView

    resetmypasswordview = ResetMyPasswordView
    resetpasswordview = ResetPasswordView
    userinfoeditview = UserInfoEditView

    rolemodelview = RoleModelView
    permissionmodelview = PermissionModelView
    userstatschartview = UserStatsChartView
    viewmenumodelview = ViewMenuModelView
    permissionviewmodelview = PermissionViewModelView

    def __init__(self,appbuilder):
        super(BaseSecurityManager,self).__init__(appbuilder)
        app = self.appbuilder.get_app

        app.config.setdefault('AUTH_ROLE_ADMIN','Admin')
        app.config.setdefault('AUTH_ROLE_PUBLIC','Public')
        app.config.setdefault('AUTH_TYPE',AUTH_DB)

        app.config.setdefault('AUTH_USER_REGISTRATION',False)
        app.config.setdefault('AUTH_USER_REGISTTAION_ROLE',self.auth_role_public)

        #LDAP config
        if self.auth_type == AUTH_LDAP:
            if 'AUTH_LDAP_SERVER' not in app.config:
                raise Exception("No AUTH_LDAP_SERVER defined on config with AUTH_LDAP authentication type.")
            app.config.setdefault('AUTH_LDAP_SEARCH','')
            app.config.setdefault('AUTH_LDAP_BIND_USER','')
            app.config.setdefault('AUTH_LDAP_APPEND_DOMAIN','')
            app.config.setdefault('AUTH_LDAP_BIND_PASSWORD','')
            app.config.setdefault('AUTH_LDAP_ALLOW_SELF_SIGNED',False)
            app.config.setdefault('AUTH_LDAP_UID_FAILED','uid')
            app.config.setdefault('AUTH_LDAP_FIRSTNAME_FIELD','givenName')
            app.config.setdefault('AUTH_LDAP_LASTNAME_FIELD','sn')
            app.config.setdefault('AUTH_LDAP_EMAIL_FIELD','mail')

        if self.auth_type == AUTH_OID:
            self.oid = OpenID(app)
        if self.auth_type == AUTH_OAUTH:
            from flask_oauthlib.client import OAuth
            self.oauth = OAuth()
            self.oauth_remotes = dict()
            for _provider in self.oauth_providers:
                provider_name = _provider['name']
                log.debug("OAuth providers init {0}".format(provider_name))
                obj_provider = self.oauth_remote_app(provider_name,**_provider['remote_app'])
                obj_provider._tokegetter = self.oauth_tokengetter
                if not self.oauth_user_info:
                    self.oauth_user_info = self.get_oauth_user_info
                self.oauth_remotes[provider_name] = obj_provider

        self.lm = LoginManager(app)
        self.lm.login_view = 'login'
        self.lm.user_loader(self.load_user)

    @property
    def get_url_for_registeruser(self):
        return url_for('%s.%s' % (self.registeruser_view.endpoint,self.registeruser_view.default_view))

    @property
    def get_user_datamodel(self):
        return self.user_view.datamodel

    @property
    def get_register_user_datamodel(self):
        return self.registerusermodelview.datamodel

    @property
    def auth_type(self):
        return self.appbuilder.get_app.config['AUTH_TYPE']

    @property
    def auth_role_admin(self):
        return self.appbuilder.get_app.config['AUTH_ROLE_ADMIN']

    @property
    def auth_role_public(self):
        return self.appbuilder.get_app.config['AUTH_ROLE_PUBLIC']

    @property
    def auth_ldap_server(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_SERVER']

    @property
    def auth_user_registration(self):
        return self.appbuilder.get_app.config['AUTH_USER_REGISTRATION']

    @property
    def auth_user_registration_role(self):
        return self.appbuilder.get_app.config['AUTH_USER_REGISTRATION_ROLE']

    @property
    def auth_ldap_search(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_SEARCH']

    @property
    def auth_ldap_bind_user(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_BIND_USER']

    @property
    def auth_ldap_bind_password(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_BIND_PASSWORD']

    @property
    def auth_ldap_append_domain(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_APPEND_DOMAIN']

    @property
    def auth_ldap_uid_field(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_UID_FIELD']

    @property
    def auth_ldap_firstname_field(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_FIRSTNAME_FIELD']

    @property
    def auth_ldap_lastname_field(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_LASTNAME_FIELD']

    @property
    def auth_ldap_email_field(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_EMAIL_FIELD']

    @property
    def auth_ldap_bind_first(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_BIND_FIRST']

    @property
    def auth_ldap_allow_self_signed(self):
        return self.appbuilder.get_app.config['AUTH_LDAP_ALLOW_SELF_SIGNED']

    @property
    def openid_providers(self):
        return self.appbuilder.get_app.config['OPENID_PROVIDERS']

    @property
    def oauth_providers(self):
        return self.appbuilder.get_app.config['OAUTH_PROVIDERS']

    def oauth_user_info_getter(self,f):

        def wraps(provider,response=None):
            ret = f(self.oauth_remotes,provider,response=response)
            if not type(ret) == dict:
                log.error("OAuth user info decorated function did not returned a dict,but:{0}".format(type(ret)))
                return {}
            return ret
        self.oauth_user_info = wraps
        return wraps

    def get_oauth_token_key_name(self,provider):
        for _provider in self.oauth_providers:
            if _provider['name'] == provider:
                return _provider.get('token_key','oauth_token')

    def get_oauth_token_secret_name(self,provider):
        for _provider in self.oauth_providers:
            if _provider['name'] == provider:
                return _provider.get('token_secret','oauth_token_secret')

    def set_oauth_session(self,provider,oauth_response):
        token_key = self.appbuilder.sm.get_oauth_token_key_name(provider)
        token_secret = self.appbuildersm.get_oauth_token_secret_name(provider)
        session['oauth'] = (
                oauth_response[token_key],
                oauth_response.get(token_secret,'')
            )
        session['oauth_provider'] = provider

    def get_oauth_user_info(self,provider,resp=None):
        """
            Since thre are different OAuth API's with different ways to retrieve user info
        """
        if provider == 'github' or provider == 'githublocal':
            me = self.appbuilder.sm.oauth_remotes[provider].get('user')
            log.debug('User info from Github:{0}'.format(me.data))
            return {'username':me.data.get('login')}

        if provider == 'twitter':
            me = self.appbuilder.sm.oauth_remotes[provider].get('account/settings.json')
            log.debug("User info from Twitter:{0}".format(me.data))
            return {'username':me.data.get('screen_name','')}

        if provider == 'linkedin':
            me = self.appbuilder.sm.oauth_remotes[provider].get('people/~:(id,email-address,first-name,last-name)?format=json')
            log.debug("User info from Linkedin:{0}".format(me.data))
            return {'username':me.data.get('id',''),
                    'email':me.data.get('email-address',''),
                    'first_name':me.data.get('firstName',''),
                    'last_name':me.data.get('lastName','')}

        if provider == 'google':
            me = self.appbuilder.sm.oauth_remotes[provider].get('people/me')
            log.debug("User info from Google:{0}".format(me.data))
            return {'username':me.data.get('displayName',''),
                    'email':me.data['emails'][0].get('value',''),
                    'first_name':me.data['name'].get('givenName',''),
                    'last_name':me.data['name'].get('familyName','')}
        else:
            return {}

    def register_views(self):
        if self.auth_user_registration:
            if self.auth_type == AUTH_DB:
                self.registeruser_view = self.registeruserdbview()
            elif self.auth_type == AUTH_OID:
                self.registeruser_view = self.registeruseroidview()
            elif self.auth_type == AUTH_OAUTH:
                self.registeruser_view = self.registeruseroauthview()
            if self.registeruser_view:
                self.appbuilder.add_view_no_menu(self.registeruser_view)

        self.appbuilder.add_view_no_menu(self.resetpasswordview())
        self.appbuilder.add_view_no_menu(self.resetmypasswordview())
        self.appbuilder.add_view_no_menu(self.userinfoeditview())

        if self.auth_type == AUTH_DB:
            self.user_view = self.userdbmodelview
            self.auth_view = self.authdbview()
        elif self.auth_type == AUTH_LDAP:
            self.user_view = self.userldapmodelview
            self.auth_view = self.authldapview()
        elif self.auth_type == AUTH_OAUTH:
            self.user_view = self.useroauthmodelview
            self.auth_view = self.authoauthview()
        elif self.auth_type == AUTH_REMOTE_USER:
            self.user_view = self.userremoteusermodelview
            self.auth_view = self.authremoteuserview()
        else:
            self.user_view = self.useroidmodelview
            self.auth_view = self.authoidview()
            if self.auth_user_registration:
                pass
                #self.registeruser_view = self.registeruseroidview()
                #self.appbuilder.add_view_no_menu(self.registeruser_view)

        self.appbuilder.add_view_no_menu(self.auth_view)

        self.user_view = self.appbuilder.add_view(self.user_view,"List Users",
                icon="fa-user",label=_("List Users"),category="Security",
                category_icon="fa=cogs",category_label=_('Security'))

        role_view = self.appbuilder.add_view(self.rolemodelview,"List Roles",
                icon="fa-group",label=_("List Users"),category="Security",category_icon="fa-cogs")
        role_view.related_views = [self.user_view.__class__]

        self.appbuilder.add_view(self.userstatschartview,"User's Statistics",
                icon="fa-bar-chart-o",label=_("User's Statistics"),category="Security")

        if self.auth_user_registration:
            self.appbuilder.add_view(self.registerusermodelview,"User's Statistics",
                    icon="fa-user-plus",label=_("User Registrations"),category="Security")

        self.appbuilder.menu.add_separator("Security")
        self.appbuilder.add_view(self.permissionmodelview,"Base Permissions",icon="fa-lock",
                label=_("Base Permission"),category="Security")
        self.appbuilder.add_view(self.viewmenumodelview,"Views/Menus",icon="fa-lock",
                label=_("Views/Menus"),category="Security")
        self.appbuilder.add_view(self.permissionviewmodelview,"Permission on Views/Menus",
                icon="fa-link",label=_('Permission on Views/Menus'),category="Security")



