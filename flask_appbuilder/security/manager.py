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


    def create_db(self):

        self.add_role(self.auth_role_admin)
        self.add_role(self.auth_role_public)
        if self.count_users() == 0:
            log.warning(LOGMSG_WAR_SEC_NO_USER)

    def reset_password(self,userid,password):
        user = self.get_user_by_id(userid)
        user.password = generate_password_hash(password)
        self.update_user(user)

    def update_user_auth_stat(self,user,success=True):
        if not user.login_count:
            user.login_count = 0
        if not user.fail_login_count:
            self.fail_login_count = 0
        if success:
            user.login_count += 1
            user.fail_login_count = 0
        else:
            user.fail_login_count += 1
        user.last_login = datetime.datetime.now()
        self.update_user(user)

    def auth_user_db(self,username,password):
        if username is None or username == "":
            return None
        user = self.find_user(username=username)
        if user is None or (not user.is_active()):
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(username))
            return None
        elif check_password_hash(user.password,password):
            self.update_user_auth_stat(user,True)
            return user
        else:
            self.update_user_auth_stat(user,False)
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(username))
            return None

    def _search_ldap(self,ldap,con,username):
        if self.auth_ldap_append_domain:
            username = username + '@' + self.auth_ldap_append_domain
        filter_str = "%s=%s" % (self.auth_ldap_uid_field,username)
        user = con.search_s(self.auth_ldap_search,
                ldap.SCOPE_SUBTREE,
                filter_str,
                [self.auth_ldap_firstname_field,
                    self.autho_ldap_lastname_field,
                    self.auth_ldap_email_field])
        if user:
            if not user[0][0]:
                return None
        return user

    def _bind_ldap(self,ldap,con,username,password):
        try:
            indirect_user = self.auth_ldap_bind_user
            if indirect_user:
                indirect_password = self.auth_ldap_bind_password
                log.debug("LDAP indirect bind with:{0}".format(indirect_user))
                con.bind_s(indirect_user,indirect_password)
                log.dubug("LDAP BIND indirect OK")
                user = self._search_ldap(ldap,con,username)
                if user:
                    log.debug("LDAP got User {0}".format(user))
                    username = user[0][0]
                else:
                    return False
            log.debug("LDAP bind with:{0} {1}".format(username,"XXXXXX"))
            if self.auth_ldap_append_domain:
                username = username + '@' + self.auth_ldap_append_domain
            con.bind_s(username,password)
            log.debug("LDAP bind OK:{0}".format(username))
            return True
        except ldap.INVALID_CREDENTIALS:
            return False

    def auth_user_ldap(self,username,password):
        if username is None or username == "":
            return None
        user = self.find_user(username=username)
        if user is not None and (not user.is_active()):
            return None
        else:
            try:
                import ldap
            except:
                raise Exception("No ldap library for python.")
                return None
            try:
                if self.auth_ldap_allow_self_signed:
                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,ldap.OPT_X_TLS_ALLOW)
                con = ldap.initialize(self.auth_ldap_server)
                con.set_option(ldap.OPT_REFERRALS,0)

                if not self._bind_ldap(ldap,con,username,password):
                    if user:
                        self.update_user_auth_stat(user,False)
                    log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(username))
                    return None
                if not user and not self.auth_user_registration:
                    return None
                elif not user and self.auth_user_registration:
                    new_user = self._search_ldap(ldap,con,username)
                    if not new_user:
                        log.warning(LOGMSG_WAR_SEC_NOLDAP_OBJ.format(username))
                        return None
                    ldap_user_info = new_user[0][1]
                    if self.auth_user_registration and user is None:
                        user = self.add_user(username=username,
                                first_name=ldap_user_info.get(self.auth_ldap_firstname_field,[username])[0],
                                last_name=ldap_user_info.get(self.auth_ldap_lastname_field,[username])[0],
                                email=ldap_user_info.get(self.auth_ldap_email_field,[username + '@email.notfound'])[0],
                                role=self.find_role(self.auth_user_registration_role)
                            )
                self.update_user_auth_stat(user)
                return user

            except ldap.LDAPError as e:
                if type(e.message) == dict and 'desc' in e.message:
                    log.error(LOGMSG_ERR_SEC_AUTH_LDAP.format(e.message['desc']))
                    return None
                else:
                    log.error(e)
                    return None

    def auth_user_oid(self,email):
        user = self.find_user(email=email)
        if user is None or (not user.is_active()):
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(email))
            return None
        else:
            self.update_user_auth_stat(user)
            return user

    def auth_user_remote_user(self,username):
        user = self.find_user(username=username)
        if user is None or (not user.is_active()):
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(username))
            return None
        else:
            self.update_user_auth_stat(user)
            return user

    def auth_user_oauth(self,userinfo):
        if 'username' in userinfo:
            user = self.find_user(username=userinfo['username'])
        elif 'email' in userinfo:
            user = self.find_user(email=userinfo['email'])
        else:
            log.error('User info does not have username or email {0}'.format(userinfo))
            return None
        if user is None or (not user.is_active()):
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(userinfo))
            return None
        else:
            self.update_user_auth_stat(user)
            return user

    """
    -----------------------
    PERMISSION ACCESS CHECK
    -----------------------
    """

    def is_item_public(self,permission_name,view_name):
        permissions = self.get_public_permissions()
        if permissions:
            for i in permissions:
                if (view_name == i.view_menu.name) and (permission_name == i.permission.name):
                    return True
            return False
        else:
            return False

    def _has_view_access(self,user,permission_name,view_name):
        roles = user.roles
        for role in roles:
            permissions = role.permissions
            if permissions:
                for permission in permissions:
                    if (view_name == permission.view_menu.name) and (permission_name == permission.permission.name):
                        return True
        return False

    def has_access(self,permission_name,view_name):
        if current_user.is_authenticated():
            return self._has_view_access(g.user,permission_name,view_name)
        else
            return self.is_item_public(permission_name,view_name)

    def add_permissions_view(self,base_permissions,view_menu):
        view_menu_db = self.add_view_menu(view_menu)
        perm_views = self.find_permissions_view_menu(view_menu_db)

        if not perm_views:
            for permission in base_permissions:
                pv = self.add_permission_view_menu(permission,view_menu)
                role_admin = self.find_role(self.auth_role_admin)
                self.add_permission_role(role_admin,pv)
        else:
            role_admin = self.find_role(self.auth_role_admin)
            for permission in base_permissions:
                if not self.exist_permission_on_views(perm_views,permission):
                    pv = self.add_permission_view_menu(permission,view_menu)
                    self.add_permission_role(role_admin,pv)
            for perm_view in perm_views:
                if perm_view.permission.name not in base_permissions:
                    roles = self.get_all_roles()
                    perm = self.find_permission(perm_view.permission.name)
                    for role in roles:
                        self.del_permission_role(role,perm)
                    self.del_permission_view_menu(perm_view.permission.name,view_menu)
                elif perm_view not in role_admin.permissions:
                    self.add_permission_role(role_admin,perm_view)

    def add_permissions_menu(self,view_menu_name):
        self.add_view_menu(view_menu_name)
        pv = self.find_permission_view_menu('menu_access',view_menu_name)
        if not pv:
            pv = self.add_permission_view_menu('menu_access',view_menu_name)
            role_admin = self.find_role(self.auth_role_admin)
            self.add_permission_role(role_admin,pv)

    def security_cleanup(self,baseviews,menus):
        viewsmenus = self.get_all_view_menu()
        roles = self.get_all_roles()
        for viewmenu in viewsmenus:
            found = False
            for baseview in baseviews:
                if viewmenu.name == baseview.__class__.__name__:
                    found = True
                    break
            if menus.find(viewmenu.name):
                found = True
            if not found:
                permissions = self.find_permissions_view_menu(viewmenu)
                for permission in permissions:
                    for role in roles:
                        self.del_permission_role(role,permission)
                    self.del_permission_view_menu(permission.permission.name,viewmenu.name)
                self.del_view_menu(viewmenu.name)


    """INTERFACE ABSTRACT METHODS
        PRIMITIVES FOR USERS
    """

    def find_register_user(self,registration_hash):
        raise NotImplementedError

    def add_register_user(self,username,first_name,last_name,email,password='',hashed_password=''):
        raise NotImplementedError

    def del_register_user(self,register_user):
        raise NotImplementedError

    def get_user_by_id(self,pk):
        raise NotImplementedError

    def find_user(self,username=None,email=None):
        raise NotImplementedError

    def get_all_users(self):
        raise NotImplementedError

    def add_user(self,username,first_name,last_name,email,role,password=''):
        raise NotImplementedError

    def update_user(self,user):
        raise NotImplementedError

    def count_users(self):
        raise NotImplementedError

    #PRIMITIVES FOR ROLES
    def find_role(self,name):
        raise NotImplementedError

    def add_role(self,name):
        raise NotImplementedError

    def get_all_roles(self):
        raise NotImplementedError

    #PRIMITIVES FOR PERMISSIONS
    def get_public_permissions(self):
        raise NotImplementedError

    def find_permission(self,name):
        raise NotImplementedError

    def add_permission(self,name):
        raise NotImplementedError

    def del_permission(self,name):
        raise NotImplementedError

    def get_public_permissions(self):
        raise NotImplementedError

    #PRIMITIVES FOR VIEW MENU
    def find_view_menu(self,name):
        raise NotImplementedError

    def get_all_view_menu(self):
        raise NotImplementedError

    def add_view_menu(self,name):
        raise NotImplementedError

    def del_view_menu(self,name):
        raise NotImplementedError

    #PERMISSION VIEW MENU
    def find_permission_view_menu(self,permission_name,view_menu_name):
        raise NotImplementedError

    def find_permissions_view_menu(self,view_menu):
        raise NotImplementedError

    def add_permission_view_menu(self,permission_name,view_menu_name):
        raise NotImplementedError

    def del_permission_view_menu(self,permission_name,view_menu_name):
        raise NotImplementedError

    def exist_permission_on_views(self,lst,item):
        raise NotImplementedError

    def exist_permission_on_view(self,lst,permission,view_menu):
        raise NotImplementedError

    def add_permission_role(self,role,perm_view):
        raise NotImplementedError

    def del_permission_role(self,role,perm_view):
        raise NotImplementedError

    def load_user(self,pk):
        return self.get_user_by_id(int(pk))

    @staticmethod
    def before_request():
        g.user = current_user





