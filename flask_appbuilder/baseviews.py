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
        f._urls.append((url,methods))
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
        self.endpoint = endpoint or self.__class__.__name__

        if self.route_base is None:
            self.route_base = '/' + self.__class__.__name__.lower()

        self.static_folder = static_folder
        if not static_folder:
            self.blueprint = Blueprint(self.endpoint,__name__,
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

    def _prettify_column(self,name):
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
    show_widget = ShowWidget

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
                    self.edit_form_query_rel_fields)

    def _init_titles(self):
        super(BaseCRUDView,self)._init_titles()

        class_name = self.datamodel.model_name
        if not self.list_title:
            self.list_title = 'List ' + self._prettify_name(class_name)
        if not self.add_title:
            self.add_title = 'Add ' + self._prettify_name(class_name)
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
        self.edit_exclude_columns = self.edit_exclude_columns or []

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

    def _get_related_views_widgets(self,item,orders=None,pages=None,page_sizes=None,widgets=None,**args):
        """
        :returns:
            Returns a dict with 'related_views' key with a list of Model View widgets
        """
        widgets = widgets or {}
        widgets['related_views'] = []
        for view in self._related_views:
            if orders.get(view.__class__.__name__):
                order_column,order_direction = orders.get(view.__class__.__name__)
            else:
                order_column,order_direction = '',''
            widgets['related_views'].append(self._get_related_view_widget(item,view,
                order_column,order_direction,
                page=pages.get(view.__class__.__name__),
                page_size=page_sizes.get(view.__class__.__name__)))
        return widgets

    def _get_view_widget(self,**kwargs):
        """
        :return:
            Returns a Model View widget
        """
        return self._get_list_widget(**kwargs).get('list')

    def _get_list_widget(self,filters,actions=None,order_column='',order_direction='',
            page=None,page_size=None,widgets=None,**args):
        widgets = widgets or {}
        actions = actions or self.actions
        page_size = page_size or self.page_size
        if not order_column and self.base_order:
            order_column,order_direction = self.base_order
        joined_filters = filters.get_joined_filters(self._base_filters)
        count,lst = self.datamodel.query(joined_filters,order_column,order_direction,page=page,page_size=page_size)
        pks = self.datamodel.get_keys(lst)
        widgets['list'] = self.list_widget(label_columns=self.label_columns,
                include_columns=self.list_columns,
                value_columns=self.datamodel.get_values(lst,self.list_columns),
                order_columns=self.order_columns,
                formatters_columns=self.formatters_columns,
                page=page,page_size=page_size,
                count=count,pks=pks,actions=actions,
                filters=filters,modelview_name=self.__class__.__name)
        return widgets

    def _get_show_widget(self,pk,item,widgets=None,actions=None,show_fieldsets=None):
        widgets = widgets or {}
        actions = actions or self.actions
        show_fieldsets = show_fieldsets or self.show_fieldsets
        widgets['show']=self.show_widget(pk=pk,
                label_columns=self.label_columns,
                include_columns=self.show_columns,
                value_columns=self.datamodel.get_values_item(item,self.show_columns),
                formatters_columns=self.formatters_columns,
                actions=actions,
                fieldsets=show_fieldsets,
                modelview_name=self.__class__.__name__)
        return widgets

    def _get_add_widget(self,form,exclude_cols=None,widgets=None):
        exclude_cols = exclude_cols or []
        widgets = widgets or {}
        widgets['add'] = self.add_widget(form=form,
                include_cols=self.add_columns,
                exclude_cols=exclude_cols,
                fieldsets=self.add_fieldsets)
        return widgets

    def _get_edit_widget(self,form,exclude_cols=None,widgets=None):
        exclude_cols = exclude_cols or []
        widgets = widgets or {}
        widgets['edit'] = self.edit_widget(form=form,
                include_cols=self.edit_columns,
                exclude_cols=exclude_cols,
                fieldsets=self.edit_fieldsets)
        return widgets

    def get_uninit_inner_views(self):
        return self.related_views

    def get_init_inner_views(self):
        return self._related_views


    """
    -----------------------------------------
        CRUD functions behaviour
    -----------------------------------------
    """

    def _list(self):
        if get_order_args().get(self.__class__.__name__):
            order_column,order_direction = get_order_args().get(self.__class__.__name__)
        else:
            order_column,order_direction = '',''
        page = get_page_args().get(self.__class__.__name__)
        page_size = get_page_size_args().get(self.__class__.__name__)
        get_filter_args(self._filters)
        widgets = self._get_list_widget(filters=self._filters,
                order_column=order_column,
                order_direction=order_direction,
                page=page,
                page_size=page_size)
        form = self.search_form.refresh()
        self.update_redirect()
        return self._get_search_widget(form=form,widgets=widgets)

    def _show(self,pk):
        pages = get_page_args()
        page_sizes = get_page_size_args()
        orders = get_order_args()

        item = self.datamodel.get(pk,self._base_filters)
        if not item:
            abort(404)
        widgets = self._get_show_widget(pk,item)
        self.update_redirect()
        return self._get_related_views_widgets(item,orders=orders,
                pages=pages,page_sizes=page_sizes,widgets=widgets)

    def _add(self):
        is_valid_form = True
        get_filter_args(self._filters)
        exclude_cols = self._filters.get_relation_cols()
        form = self.add_form.refresh()

        if request.method == 'POST':
            self._fill_form_exclude_cols(exclude_cols,form)
            if form.validate():
                item = self.datamodel.obj()
                form.populate_obj(item)

                try:
                    self.pre_add(item)
                except Exception as e:
                    flash(str(e),"danger")
                else:
                    if self.datamodel.add(item):
                        self.post_add(item)
                    flash(*self.datamodel.message)
                finally:
                    return None
            else:
                is_valid_form = False
        if is_valid_form:
            self.update_redirect()
        return self._get_add_widget(form=form,exclude_cols=exclude_cols)

    def _edit(self,pk):
        is_valid_form = True
        pages = get_page_args()
        page_sizes = get_page_size_args()
        orders = get_order_args()
        get_filter_args(self._filters)
        exclude_cols = self._filters.get_relation_cols()

        item = self.datamodel.get(pk,self._base_filters)
        if not item:
            abort(404)
        #convert pk to correct type,if pk is non string type.
        pk = self.datamodel.get_pk_value(item)

        if request.method == 'POST':
            form = self.edit_form.refresh(request.form)
            self._fill_form_exclude_cols(exclude_cols,form)
            form._id = pk
            if form.validate():
                form.populate_obj(item)
                try:
                    self.pre_update(item)
                except Exception as e:
                    flash(str(e),"danger")
                else:
                    if self.datamodel.edit(item):
                        self.post_update(item)
                    flash(*self.datamodel.message)
                finally:
                    return None
            else:
                is_valid_form = False
        else:
            form = self.edit_form.refresh(obj=item)
        widgets = self._get_edit_widget(form=form,exclude_cols=exclude_cols)
        widgets = self._get_related_views_widgets(item,filters={},
                    orders=orders,pages=pages,page_sizes=page_sizes,widgets=widgets)
        if is_valid_form:
            self.update_redirect()
        return widgets

    def _delete(self,pk):
        item = self.datamodel.get(pk,self._base_filters)
        if not item:
            abort(404)
        try:
            self.pre_delete(item)
        except Exception as e:
            flash(str(e),"danger")
        else:
            if self.datamodel.delete(item):
                self.post_delete(item)
            flash(*self.datamodel.message)
            self.update_redirect()

    """
    -----------------------------------
        HELPER FUNCTIONS
    -----------------------------------
    """
    def _fill_form_exclude_cols(self,exclude_cols,form):
        for filter_key in exclude_cols:
            filter_value = self._filters.get_filter_value(filter_key)
            rel_obj = self.datamodel.get_related_obj(filter_key,filter_value)
            field = getattr(form,filter_key)
            field.data = rel_obj

    def pre_update(self,item):
        pass

    def post_update(self,item):
        pass

    def pre_add(self,item):
        pass

    def post_add(self,item):
        pass

    def pre_delete(self,item):
        pass

    def post_delete(self,item):
        pass

