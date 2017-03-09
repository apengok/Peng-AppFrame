import logging
import functools

from flask import flash,redirect,url_for,make_response,jsonify
from .._compat import as_unicode
from ..const import LOGMSG_ERR_SEC_ACCESS_DENIED,FLAMSG_ERR_SEC_ACCESS_DENIED,PERMISSION_PREFIX

log = logging.getLogger(__name__)


def has_access(f):
    """
    By default the permission's name is the methods name.
    """
    if hasattr(f,'_permission_name'):
        permission_str = f._permission_name
    else:
        permission_str = f.__name__

    def wraps(self,*args,**kwargs):
        permission_str = PERMISSION_PREFIX + f._permission_name
        if self.appbuilder.sm.has_access(permission_str,self.__class__.__name__):
            return f(self,*args,**kwargs)
        else:
            log.warning(LOGMSG_ERR_SEC_ACCESS_DENIED.format(permission_str,self.__class__.__name__))
            flash(as_unicode(FLAMSG_ERR_SEC_ACCESS_DENIED),"danger")
        return redirect(url_for(self.appbuilder.sm.auth_view.__class__.__name__ + ".login"))
    f._permission_name = permission_str
    return functools.update_wrapper(wraps,f)


def has_access_api(f):
    if hasattr(f,'_permission_name'):
        permission_str = f._permission_name
    else:
        permission_str = f.__name__

    def wraps(self,*args,**kwargs):
        permission_str = PERMISSION_PREFIX + f._permission_name
        if self.appbuilder.sm.has_access(permission_str,self.__class__.__name__):
            return f(self,*args,**kwargs)
        else:
            log.warning(LOGMSG_ERR_SEC_ACCESS_DENIED.format(permission_str,self.__class__.__name__))
            response = make_response(jsonify({'message':str(FLAMSG_ERR_SEC_ACCESS_DENIED),
                'severity':'danger'}),401)
            response.headers['Content-Type'] = "application/json"
            return response
        return redirect(url_for(self.appbuilder.sm.auth_view.__class__.__name__ + ".login"))
    f._permission_name = permission_str
    return functools.update_wrapper(wraps,f)


def permission_name(name):
    def wraps(f):
        f._permission_name = name
        return f
    return wraps
