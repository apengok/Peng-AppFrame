import logging

from flask import Blueprint,url_for,current_app
from .views import IndexView,UtilView
from .filters import TemplateFilters
from .menu import Menu
from .babel.manager import BabelManager
from .version import VERSION_STRING
from .const import LOGMSG_WAR_FAB_VIEW_EXISTS,\
        LOGMSG_ERR_FAB_ADD_PERMISSION_MENU,\
        LOGMSG_INF_FAB_ADD_VIEW,\
        LOGMSG_ERR_FAB_ADD_PERMISSION_VIEW,\
        LOGMSG_INF_FAB_ADDON_ADDER,\
        LOGMSG_ERR_FAB_ADDON_IMPORT,\
        LOGMAG_ERR_FAB_ADDON_PROCESS


log = logging.getLogger(__name__)


def dynamic_class_import(class_path):
    """
        Will dynamically import a class from a string path
        :param class_path:string with class path
        :return:class
    """
    #Split first occurrence of path
    try:
        tmp = class_path.split('.')
        module_path = '.'.join(tmp[0:-1])
        package = __import__(module_path)
        return reduce(getattr,tmp[1:],package)
    except Exception as e:
        log.error(LOGMSG_ERR_FAB_ADD0N_IMPORT.format(class_path,e))


