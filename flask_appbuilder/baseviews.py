import logging
from flask import Blueprint,session,flash,render_template,url_for,abort
from ._compat import as_unicode
from .forms import GeneralModelConverter
from .widgets import FormWidget,ShowWidget,ListWidget,SearchWidget
from .actions import ActionItem
from .urltools import *

log = logging.getLogger(__name__)


def expose(url='/',methods=('GET',)):
    """
        Use this decorator to expose views on your view classes.

        :param url: Relative URL for the view
        :param methods: Allowed HTTP methods.By default only GEET is allowed.
    """

    def wrap(f):
        if not hasattr(f,'_urls'):
            f._urls = []
            return f
    return wrap

def expose_api(name='',url='',methods=('GET',),description=''):
    def wrap(f):
        api_name = name or f.__name__
        api_url = url or "/api/{0}".format(name)
        if not hasattr(f,'_urls'):
            f._urls = []
            f._extra = {}
        f._urls.append((api_url,methods))
        f._extra[api_name] = (api_url,f.__name__,description)
        return f
    return wrap


class BaseView(object):
    """
        All views inherit from this class.
        It's constructor will register your exposed urls on flask as a Blueprint.
        This class does not expose any urls,but provideds a common base for all views.
        Extend this class if you want to expose methods for your own templates
    """

    appbuilder = None
    blueprint = None
    endpoint = None

    route_base = None
    """ Override this if you want to define your own relative url"""

    template_folder = 'templates'
    """ the template folder relative lacation """
    static_folder = 'static'
    base_permissions = None
    """
        List with allowed base permission.
        Use it like this if you want to restrict your view to readonly::

            class MyView(ModelView):
                base_permissions = ['can_list','can_show']
    """

    default_view = 'list'
    """ the default view for this BaseView,to be used with url_for (method name)"""
    extra_args = None

    """ dictionary for injecting extra arguments into template """
    _apis = None

    def __init__(self):

        if self.base_permissions is None:
            self.base_permissions = set()
            for attr_name in dir(self):
                if hasattr(getattr(self,attr_name),'_permission_name'):
                    permission_name = getattr(getattr(self,attr_name),'_permission_name')
                    self.base_permissions.add('can_' + permission_name)
            self.base_permissions = list(self.base_permissions)
        if not self.extra_args:
            self.extra_args = dict()
        self._apis = dict()
        for attr_name in dir(self):
            if hasattr(getattr(self,attr_name),'_extra'):
                _extra = getattr(getattr(self,attr_name),'_extra')
                for key in _extra:self._apis[key] = _extra[key]

    def create_blueprint(self,appbuilder,endpoint=None,static_folder=None):
        #store appbuilder instance
        self.appbuilder = appbuilder

        #if endpoint name is not provided,getit from the class name
        self.endppint = endpoint or self.__class__.__name__

        if self.route_base is None:
            self.route_base = '/' + self.__class__.__name__.lower()

        self.static_folder = static_folder
        if not static_folder:
            self.blueprint = Bluepirnt(self.endpoint,__name__,
                    url_prefix=self.route_base,
                    template_folder=self.template_folder)
        else:
            self.blueprint = Blueprint(self.endpoint,__name__,
                    url_prefix=self.route_base,
                    template_folder=self.template_folder,
                    static_folder=static_folder)
        self._register_urls()
        return self.blueprint

    def _register_urls(self):
        for attr_name in dir(self):
            attr = getattr(self,attr_name)
            if hasattr(attr,'_urls'):
                for url,methods in attr._urls:
                    self.blueprint.add_url_rule(url,
                            attr_name,
                            attr,
                            methods=methods)

    def render_template(self,template,**kwargs):
        kwargs['base_template'] = self.appbuilder.base_template
        kwargs['appbuilder'] = self.appbuilder
        return render_template(template,**dict(list(kwargs.items()) + list(self.extra_args.items())))

    def _prettify_name(self,name):
        return re.sub(r'(?<=.)([A-Z])',r' \1',name)

    def _prittify_column(self,name):
        return re.sub('[._]',' ',name).title()

    def update_redirect(self):
        page_history = Stack(session.get('page_history',[]))
        page_history.push(request.url)
        session['page_history'] = page_history.to_json()

    def get_redirect(self):
        index_url = self.appbuilder.get_url_for_index
        page_history = Stack(session.get('page_history',[]))

        if page_history.pop() is None:
            return index_url
        session['page_history'] = page_history.to_json()
        url = page_history.pop() or index_url
        return url

    @classmethod
    def get_default_url(cls,**kwargs):
        return url_for(cls.__name__ + '.' + cls.default_view,**kwargs)

    def get_uninit_inner_views(self):
        return []

    def get_init_inner_views(self,views):
        pass


class BaseFormView(BaseView):
    form_template = 'appbuilder/general/model/edit.html'

    edit_widget = FormWidget
    """ Form widget to override """
    form_title = ''
    """ the form title to be displayed """
    form_columns = None
    """ The form columns to include,if empty will include all"""
    form = None
    """ The WTF form to render """
    form_fieldsets = None
    default_view = 'this_form_get'
    """ The form view default enty endpoint """

    def _init_vars(self):
        self.form_columns = self.form_columns or []
        self.form_fieldsets = self.form_fieldsets or []
        list_cols = [field.name for field in self.form.refresh()]
        if self.form_fieldsets:
            self.form_columns = []
            for fieldset_item in self.form_fieldsets:
                self.form_columns = self.form_columns + list(fieldset_item[1].get('fields'))
        else:
            if not self.form_columns:
                self.form_columns = list_cols

    def form_get(self,form):
        """Override this method to implement your form processing
        """
        pass

    def form_post(self,form):
        pass

    def _get_edit_widget(self,form=None,exclude_cols=None,widgets=None):
        exclude_cols = exclude_cols or []
        widgets = widgets or {}
        widgets['edit'] = self.edit_widget(route_base=self.route_base,
                form=form,
                include_cols=self.form_columns,
                exclude_cols=exclude_cols,
                fieldsets=self.form_fieldsets
                )
        return widgets


class BaseModelView(BaseView):
    """
            The base class of ModelView and ChartView, all properties are inherited
                    Customize ModelView and ChartView overriding this properties

                            This class supports all the basics for query
    """
    datamodel = None
    """
        Your sqla model you must initialize it like::
            class MyView(ModelView):
                datamodel = SQLAInterface(MyTable)
    """

    title = 'Title'

    search_columns = None
    search_exclude_columns = None
    search_form_extra_fields = None
    search_form_query_rel_fields = None
    label_columns = None
    search_form = None
    base_filters = None
    base_order = None
    search_widget = SearchWidget
    _base_filters = None
    _filters = None

    def __init__(self,**kwargs):
        datamodel = kwargs.get('datamodel',None)
        if datamodel:
            self.datamodel = datamodel
        self._init_properties()
        self._init_forms()
        self._init_titles()
        super(BaseModelView,self).__init__(**kwargs)

    def _gen_labels_columns(self,list_columns):
        for col in list_columns:
            if not self.label_columns.get(col):
                self.label_columns[col] = self._prettify_column(col)

    def _init_titles(self):
        pass

    def _init_properties(self):
        self.label_columns = self.label_columns or {}
        self.base_filters = self.base_filters or []
        self.search_exclude_columns = self.search_exclude_columns or []
        self.search_columns = self.search_columns or []

        self._base_filters = self.datamodel.get_filters().add_filter_list(self.base_filters)
        list_cols = self.datamodel.get_columns_list()
        search_columns = self.datamodel.get_search_columns_list()
        if not self.search_columns:
            self.search_columns = [x for x in search_columns if x not in self.search_exclude_columns]
        self._gen_labels_columns(list_cols)
        self._filters = self.datamodel.get_filters(self.search_columns)

    def _init_forms(self):
        conv = GeneralModelConverter(self.datamodel)
        if not self.search_form:
            self.search_form = conv.create_form(self.label_columns,
                    self.search_columns,
                    extra_fields=self.search_form_extra_fields,
                    filter_rel_fields=self.search_form_query_rel_fields)

    def _get_search_widget(self,form=None,exclude_cols=None,widgets=None):
        exclude_cols = exclude_cols or []
        widgets = widgets or {}
        widgets['search'] = self.search_widget(route_base=self.route_base,
                form=form,
                include_cols=self.search_columns,
                exclude_cols=exclude_cols,
                filters=self._filters
            )
        return widgets

    def _label_columns_json(self):
        ret = {}
        for key,value in list(self.label_columns.items()):
            ret[key] = as_unicode(value.encode('UTF-8'))
        return ret


class BaseCRUDView(BaseModelView):

    related_views = None
    _related_views = None
    list_title = ""
    show_title = ""
    add_title = ""
    edit_title = ""
    list_columns = None
    show_columns = None
    add_columns = None
    edit_columns = None
    show_exclude_columns = None
    add_exclude_columns = None
    edit_exclude_columns = None
    order_columns = None
    page_size = 10
    show_fieldsets = None
    add_fieldsets = None
    edit_fieldsets = None
    description_columns = None
    validators_columns = None
    formatters_columns = None
    add_form_extra_fields = None
    edit_form_extra_fields = None
    add_form_query_rel_fields = None
    edit_form_query_rel_fields = None

    add_form = None
    edit_form = None

    list_template = 'appbuilder/general/model/list.html'
    edit_template = 'appbuilder/general/model/edit.html'
    add_template = 'appbuilder/general/model/add.html'
    show_template = 'appbuilder/general/model/show.html'

    list_widget = ListWidget
    edit_widget = FormWidget
    add_widget = FormWidget
    show_widgete = ShowWidget

    actions = None

    def __init__(self,**kwargs):
        super(BaseCRUDView,self).__init__(**kwargs)

        self.actions = {}
        for attr_name in dir(self):
            func = getattr(self,attr_name)
            if hasattr(func,'_action'):
                action = ActionItem(*func._action,func=func)
                self.base_permissions.append(action.name)
                self.actions[action.name] = action

    def _init_forms(self):
        super(BaseCRUDView,self)._init_forms()
        conv = GeneralModelConverter(self.datamodel)
        if not self.add_form:
            self.add_form = conv.create_form(self.label_columns,
                    self.add_columns,
                    self.description_columns,
                    self.validators_columns,
                    self.add_form_extra_fields,
                    self.add_form_query_rel_fields)
        if not self.edit_form:
            self.edit_form = conv.create_form(self.label_columns,
                    self.edit_columns,
                    self.description_columns,
                    self.validators_columns,
                    self.edit_form_extra_fields,
                    self.edit_from_query_rel_fields)

    def _init_titles(self):
        super(BaseCRUDView,self)._init_titles()

        class_name = self.datamodel.model_name
        if not self.list_title:
            self.list_title = 'List ' + self._prettify_name(class_name)
        if not self.add_title:
            self.add_title = 'Add ' + self._prittify_name(class_name)
        if not self.edit_title:
            self.edit_title = 'Edit ' + self._prettify_name(class_name)
        if not self.show_title:
            self.show_title = 'Show ' + self._prettify_name(class_name)
        self.title = self.list_title

    def _init_properties(self):
        super(BaseCRUDView,self)._init_properties()

        self.related_views = self.related_views or []
        self._related_views = self._related_views or []
        self.description_columns = self.description_columns or {}
        self.validators_columns = self.validators_columns or {}
        self.formatters_columns = self.formatters_columns or {}
        self.add_form_extra_fields = self.add_form_extra_fields or {}
        self.edit_form_extra_fields = self.edit_form_extra_fields or {}
        self.show_exclude_columns = self.show_exclude_columns or []
        self.add_exclude_columns = self.add_exclude_columns or []
        self.edit_exclcude_columns = self.edit_exclude_columns or []

        list_cols = self.datamodel.get_user_columns_list()
        self.list_columns = self.list_columns or [list_cols[0]]
        self._gen_labels_columns(self.list_columns)
        self.order_columns = self.order_columns or self.datamodel.get_order_columns_list(list_columns=self.list_columns)
        if self.show_fieldsets:
            self.show_columns = []
            for fieldset_item in self.show_fieldsets:
                self.show_columns = self.show_columns + list(fieldset_item[1].get('fields'))
        else:
            if not self.show_columns:
                self.show_columns = [x for x in list_cols if x not in self.show_exclude_columns]
        if self.add_fieldsets:
            self.add_columns = []
            for fieldset_item in self.add_fieldsets:
                self.add_columns = self.add_columns + list(fieldset_item[1].get('fields'))
        else:
            if not self.add_columns:
                self.add_columns = [x for x in list_cols if x not in self.add_exclude_columns]
        if self.edit_fieldsets:
            self.edit_columns = []
            for fieldset_item in self.edit_fieldsets:
                self.edit_columns = self.edit_columns + list(fieldset_item[1].get('fields'))
        else:
            if not self.edit_columns:
                self.edit_columns = [x for x in list_cols if x not in self.edit_exclude_columns]


    """
    -------------------------------------------------------
        GET WIDGETS SECTION
    -------------------------------------------------------
    """

    def _get_related_view_widget(self,item,related_view,order_column='',order_direction='',
            page=None,page_size=None):
        fk = related_view.datamodel.get_related_fk(self.datamodel.obj)
        filters = related_view.datamodel.get_filters()
#check if it's a many to one model relation
        if related_view.datamodel.is_relation_many_to_one(fk):
            filters.add_filter_related_view(fk,self.datamodel.FilterRelationOneToManyEqual,
                    self.datamodel.get_pk_value(item))
        elif related_view.datamodel.is_relation_many_to_many(fk):
            filters.add_filter_related_view(fk,self.datamodel.FilterRelationManyToManyEqual,
                    self.datamodel.get_pk_value(item))
        else:
            log.error("Can't find relation on related view {0}".format(related_view.name))
            return None
        return related_view._get_view_widget(filters=filters,
                order_column=order_column,
                order_direction=order_direction,
                page=page,page_size=page_size)
