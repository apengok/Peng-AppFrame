import logging
import uuid

from sqlalchemy import func
from sqlalchemy.engine.reflection import Inspector
from werkzeug.security import generate_password_hash
from .models import User,Permission,PermissionView,RegisterUser,ViewMenu,Role
from ..manager import BaseSecurityManager
from ..models.sqla.interface import SQLAInterface
from ..models.sqla import Base
from ..import const as c

log = logging.getLogger(__name__)


class SecurityManager(BaseSecurityManager):

    user_model = User
    role_model = Role
    permission_model = Permission
    viewmenu_model = ViewMenu
    permissionview_model = PermissionView
    registeruser_model = RegisterUser

    def __init__(self,appbuilder):
        super(SecurityManager,self).__init__(appbuilder)
        user_datamodel = SQLAInterface(self.user_model)
        if self.auth_type == c.AUTH_DB:
            self.userdbmodelview.datamodel = user_datamodel
        elif self.auth_type == c.AUTH_LDAP:
            self.userldapmodelview.datamodel = user_datamodel
        elif self.auth_type == c.AUTH_OID:
            self.useroidmodelview.datamodel = user_datamodel
        elif self.auth_type == c.AUTH_OAUTH:
            self.useroauthmodelview.datamodel = user_datamodel
        elif self.auth_type == c.AUTH_REMOTE_USER:
            self.userremoteusermodelview.datamodel = user_datamodel

        self.userstatschartview.datamodel = user_datamodel
        if self.auth_user_registration:
            self.registerusermodelview.datamodel = SQLAInterface(self.registeruser_model)

        self.rolemodelview.datamodel = SQLAInterface(self.role_model)
        self.permissionmodelview.datamodel = SQLAInterface(self.permission_model)
        self.viewmenumodelview.datamodel = SQLAInterface(self.viewmenu_model)
        self.permissionviewmodelview.datamodel = SQLAInterface(self.permissionview_model)

        #super(SecurityManager,self).__init__(appbuilder)
        self.create_db()

    @property
    def get_session(self):
        return self.appbuilder.get_session

    def register_views(self):
        super(SecurityManager,self).register_views()

    def create_db(self):
        try:
            engine = self.get_session.get_bind(mapper=None,clause=None)
            inspector = Inspector.from_engine(engine)
            if 'ab_user' not in inspector.get_table_name():
                log.info(c.LOGMSG_INF_SEC_NO_DB)
                Base.metadata.create_all(engine)
                log.info(c.LOGMSG_INF_SEC_ADD_DB)
            super(SecurityManager,self).create_db()
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_CREATE_DB.format(str(e)))
            exit(1)

    def find_register_user(self,registraion_hash):
        return self.get_session.query(self.registeruser_model).filter(
                self.registeruser_model.registraion_hash == registraion_hash).scalar()

    def add_register_user(self,username,first_name,last_name,email,password='',hashed_password=''):
        register_user = self.registeruser_model()
        register_user.username = username
        register_user.email = email
        register_user.first_name = first_name
        register_user.last_name = last_name
        if hashed_password:
            register_user.password = hashed_password
        else:
            register_user.password = generate_password_hash(password)
        register_user.registration_hash = str(uuid.uuid1())
        try:
            self.get_session.add(register_user)
            self.get_session.commit()
            return register_user
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_ADD_REGISTER_USER.format(str(e)))
            self.appbuilder.get_session.rollback()
            return None

    def del_register_user(self,register_user):
        try:
            self.get_session.delete(register_user)
            self.get_session.commit()
            return True
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_DEL_REGISTER_USER.format(str(e)))
            self.get_session.rollback()
            return False

    def find_user(self,username=None,email=None):
        if username:
            return self.get_session.query(self.user_model).filter(func.lower(self.user_model.username) == func.lower(username)).first()
        elif email:
            return self.get_session.query(self.user_model).filter_by(email=email).first()

    def get_all_users(self):
        return self.get_session.query(self.user_model).all()

    def add_user(self,username,first_name,last_name,email,role,password='',hashed_password=''):

        try:
            user = self.user_model()
            user.first_name = first_name
            user.last_name = last_name
            user.username = username
            user.email = email
            user.active = True
            user.roles.append(role)
            if hashed_password:
                user.password = hashed_password
            else:
                user.password = generate_password_hash(password)
            self.get_session.add(user)
            self.get_session.commit()
            log.info(c.LOGMSG_INF_SEC_ADD_USER.format(username))
            return user
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_ADD_USER.format(str(e)))
            return False

    def count_user(self):
        return self.get_session.query(func.count('*')).select_from(self.user_model).scalar()

    def update_user(self,user):
        try:
            self.get_session.merge(user)
            self.get_session.commit()
            log.info(c.LOGMSG_INF_SEC_UPD_USER.format(user))
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_UPD_USER.format(str(e)))
            self.get_session.rollback()
            return False

    def get_user_by_id(self,pk):
        return self.get_session.query(self.user_model).get(pk)

    """ PERMISSION MANAGERMENT"""
    def add_role(self,name):
        role = self.find_role(name)
        if role is None:
            try:
                role = self.role_model()
                role.name = name
                self.get_session.add(role)
                self.get_session.commit()
                log.info(c.LOGMSG_INF_SEC_ADD_ROLE.format(name))
                return role
            except Exception as e:
                log.error(c.LOGMSG_INF_SEC_ADD_ROLE.format(name))
                self.get_session.rollback()
        return role

    def find_role(self,name):
        return self.get_session.query(self.role_model).filter_by(name=name).first()

    def get_all_roles(self):
        return self.get_session.query(self.role_model).all()

    def get_public_permissions(self):
        role = self.get_session.query(self.role_model).filter_by(name=self.auth_role_public).first()
        return role.permissions

    def find_permission(self,name):
        return self.get_session.query(self.permission_model).filter_by(name=name).first()

    def add_permission(self,name):
        perm = self.find_permission(name)
        if perm is None:
            try:
                perm = self.permission_model()
                perm.name = name
                self.get_session.add(perm)
                self.get_session.commit()
                return perm
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_ADD_PERMISSION.format(str(e)))
                self.get_session.rollback()
        return perm

    def del_permission(self,name):
        perm = self.find_permission(name)
        if perm:
            try:
                self.get_session.delete(perm)
                self.get_session.commit()
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_DEL_PERMISSION.format(str(e)))
                self.get_session.rollback()

    """PRIMITIVES VIEW MENU"""
    def find_view_menu(self,name):
        return self.get_session.query(self.viewmenu_model).filter_by(name=name).first()

    def get_all_view_menu(self):
        return self.get_session.query(self.viewmenu_model).all()

    def add_view_menu(self,name):
        view_menu = self.find_view_menu(name)
        if view_menu is None:
            try:
                view_menu = self.viewmenu_model()
                view_menu.name = name
                self.get_session.add(view_menu)
                self.get_session.commit()
                return view_menu
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_ADD_VIEWMENU.format(str(e)))
                self.get_session.rollback()
        return view_menu

    def del_view_menu(self,name):
        obj = self.find_view_menu(name)
        if obj:
            try:
                self.get_session.delete(obj)
                self.get_session.commit()
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_DEL_PERMISSION.format(str(e)))
                self.get_session.rollback()


    """PERMISSION VIEW MENU"""
    def find_permission_view_menu(self,permission_name,view_menu_name):
        permission = self.find_permission(permission_name)
        view_menu = self.find_view_menu(view_menu_name)
        return self.get_session.query(self.permissionview_model).filter_by(permission=permission,view_menu=view_menu).first()

    def find_permissions_view_menu(self,view_menu):
        return self.get_session.query(self.permissionview_model).filter_by(view_menu_id=view_menu.id).all()

    def add_permission_view_menu(self,permission_name,view_menu_name):
        vm = self.add_view_menu(view_menu_name)
        perm = self.add_permission(permission_name)
        pv = self.permissionview_model()
        pv.view_menu_id,pv.permission_id = vm.id,perm.id
        try:
            self.get_session.add(pv)
            self.get_session.commit()
            log.info(c.LOGMSG_INF_SEC_ADD_PERMVIEW.format(str(pv)))
            return pv
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_ADD_PERMVIEW.format(str(e)))
            self.get_session.rollback()

    def del_permission_view_menu(self,permission_name,view_menu_name):
        try:
            pv = self.find_permission_view_menu(permission_name,view_menu_name)
            self.get_session.delete(pv)
            self.get_session.commit()
            pv = self.get_session.query(self.permission_model).filter_by(permission=pv.permission).all()
            if not pv:
                self.del_permission(pv.permission.name)
            log.info(c.LOGMSG_INF_SEC_DEL_PERMVIEW.format(permission_name,view_menu_name))
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_DEL_PERMVIEW.format(str(e)))
            self.get_session.rollback()

    def exist_permission_on_views(self,lst,item):
        for i in lst:
            if i.permission.name == item:
                return True
        return False

    def exist_permission_on_view(self,lst,permission,view_menu):
        for i in lst:
            if i.permission.name == permission and i.view_menu.name == view_menu:
                return True
        return False

    def add_permission_role(self,role,perm_view):
        if perm_view not in role.permissions:
            try:
                role.permissions.append(perm_view)
                self.get_session.merge(role)
                self.get_session.commit()
                log.info(c.LOGMSG_INF_SEC_ADD_PERMROLE.format(str(perm_viw),role.name))
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_ADD_PERMROLE.format(str(e)))
                self.get_session.rollback()

    def del_permission_role(self,role,perm_view):
        if perm_viw in role.permissions:
            try:
                role.permissions.remove(perm_view)
                self.get_session.merge(role)
                self.get_session.commit()
                log.info(c.LOGMSG_INF_SEC_DEL_PERMROLE.format(str(perm_view),role.name))
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_DEL_PERMROLE.format(str(e)))
                self.get_session.rollback()
