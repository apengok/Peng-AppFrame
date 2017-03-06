import datetime
import logging
from functools import reduce
from flask_babel import lazy_gettext
from .filters import Fileters


log = logging.getLogger(__name__)


class BaseInterface(object):
    """
        Base class for all data model interface.
        Sub class it to implement your own interface for some data engine.
    """
    obj = None


    filter_converter_class = None
    """ when sub classing override with your own custom filter converter"""

    """ Messages to display on CRUD Events"""
    add_row_message = lazy_gettext('Added Row')
    edit_row_message = lazy_gettext('Changged Row')
    delete_row_message = lazy_gettext('Deleted Row')
    delete_integrity_error_message = lazy_gettext('Associated data exists,please delete them first')
    add_integrity_error_message = lazy_gettext('Integrity error,probably unique constraint')
    edit_integrity_error_message = lazy_gettext('Integrity error<Plug>PeepOpenrobably unique constraint')
    general_error_message = lazy_gettext('General Error')

    """ Tuple with message and text with severity type ex:("Added Row","info")"""
    message = ()


    def __init__(self,obj):
        self.obj = obj


    def _get_attr_value(self,item,col):
        if not hasattr(item,col):
            #it's an inner obj attr
            try:
                return reduce(getattr,col.split('.'),item)
            except Exception as e:
                return ''
        if hasattr(getattr(item,col),'__call__'):
            #its a function
            return getattr(item,col)()
        else:
            #its an attribute
            return getattr(item,col)


    def get_filters(self,search_columns=None):
        search_columns = search_columns or []
        return Filters(self.filter_converter_class,self,search_columns)


    def get_values_item(self,item,show_columns):
        return [self._get_attr_value(item,col) for col in show_columns]


    def _get_values(self,lst,list_columns):
        """
            Get Values:formats values for list template.
            returns [{'col_name':'col_value',....},{'col_name':'col_value',....}]

            :param lst:The list of item objects from query
            :param list_columns:The list of columns to include
        """
        retlst = []
        for item in lst:
            retdict = {}
            for col in list_columns:
                retdict[col] = self._get_attr_value(item,col)
            retlst.append(retdict)
        return retlst


    def get_values(self,lst,list_columns):
        """
             Get Values: formats values for list template.
             returns [{'col_name':'col_value',....},{'col_name':'col_value',....}]

             :param lst:
                 The list of item objects from query
             :param list_columns:
                 The list of columns to include
        """

        for item in lst:
            retdict = {}
            for col in list_columns:
                retdict[col] = self._get_attr_value(item,col)
            yield retdict


    def get_values_json(self,lst,list_columns):
        """Converts list of objects from query to JSON"""
        result = []
        for item in self.get_values(lst,list_columns):
            for key,value in list(item.items()):
                if isinstance(value,datetime.datetime) or isinstance(value,datetime.date):
                    value = value.isoformat()
                    item[key] = value
                if isinstance(value,list):
                    item[key] = [str(v) for v in value]
            result.append(item)
        return result


    """
        Return the models class name
        useful for auto title on views
    """
    @property
    def model_name(self):
        return self.obj.__class__.__name__



    """ Next methods must be overridden """
    def query(self,filters=None,order_column='',order_direction='',page=None,page_size=None):
        pass


    def is_image(self,col_name):
        return False


    def is_file(self,col_name):
        return False


    def is_gridfs_filter(self,col_name):
        return False


    def is_gridfs_image(self,col_name):
        return False


    def is_string(self,col_name):
        return False


    def is_text(self,col_name):
        return False


    def is_integer(self,col_name):
        return False


    def is_numeric(self,col_name):
        return False


    def is_float(self,col_name):
        return False


    def is_boolean(self,col_name):
        return False


    def is_date(self,col_name):
        return False


    def is_datetiem(self,col_name):
        return False
