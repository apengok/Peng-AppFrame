import logging
import json
from flask import (flash,redirect,send_file,jsonify,make_response,url_for,session,abort)
from ._compat import as_unicode
from .filemanager import uuid_originalname
from .widgets import GroupFormListWidget,ListMasterWidget
from .baseviews import BaseView,BaseCRUDView,BaseFormView,expose,expose_api
from .security.decorators import has_access,permission_name,has_access_api
from .urltools import *
from .const import FLAMSG_ERR_SEC_ACCESS_DENIED

log = logging.getLogger(__name__)


class IndexView(BaseView):
    route_base = ''
    default_view = 'index'
    index_template = 'appbuilder/index.html'

    @expose('/')
    def index(self):
        self.update_redirect()
        return self.render_template(self.index_template,appbuilder=self.appbuilder)


class UtilView(BaseView):
    route_base = ''
    default_view = 'back'

    @expose('/back')
    def back(self):
        return redirect(self.get_redirect())


class SimpleFormView(BaseFormView):
    @expose("/form",methods=['GET'])
    @has_access
    def this_form_get(self):
        self._init_vars()
        form = self.form.refresh()

        self.form_get(form)
        widgets = self._get_edit_widget(form=form)
        self.update_redirect()
        return self.render_template(self.form_template,
                title = self.form_title,
                widgets=widgets,
                appbuilder=self.appbuilder
            )

    @expose("/form",methods=['POST'])
    @has_access
    def this_form_post(self):
        self._init_vars()
        form = self.form.refresh()

        if form.validate_on_submit():
            response = self.form_post(form)
            if not response:
                return redirect(self.get_redirect())
            return response
        else:
            widgets = self._get_edit_widget(form=form)
            return self.render_template(self.form_template,
                    title=self.form_title,
                    widgets=widgets,
                    appbuilder=self.appbuilder
                )


class PublishFormView(BaseFormView):

    @expose("/form",methods=['GET'])
    def this_form_get(self):
        self._init_vars()
        form = self.form.refresh()
        self.form_get(form)
        widgets = self._get_edit_widget(form=form)
        self.update_redirect()
        return self.render_template(self.form_template,
                title=self.form_title,
                widgets=widgets,
                appbuilder=self.appbuilder
            )

    @expose("/form",methods=['POST'])
    def this_form_post(self):
        self._init_vars()
        form = self.form.refresh()
        if form.validate_on_submit():
            response = self.form_post(form)
            if not response:
                return redirect(self.get_redirect())
            return response
        else:
            widgets = self._get_edit_widget(form=form)
            return self.render_template(self.form_template,
                    title=self.form_title,
                    widgets=widgets,
                    appbuilder=self.appbuilder
                )


class RestCRUDView(BaseCRUDView):
    """
        This class view exposes REST method for CRUD operations on you models
    """

    def _search_form_json(self):
        pass

    def _get_api_urls(self,api_urls=None):

        view_name = self.__class__.__name__
        api_urls = api_urls or {}
        api_urls['read'] = url_for(view_name + ".api_read")
        api_urls['delete'] = url_for(view_name + ".api_delete",pk="")
        api_urls['create'] = url_for(view_name + ".api_create")
        api_urls['update'] = url_for(view_name + ".api_update",pk="")
        return api_urls

    def _get_modelview_urls(self,modelview_urls=None):
        view_name = self.__class__.__name__
        modelview_urls = modelview_urls or {}
        modelview_urls['show'] = url_for(view_name + ".show",pk="")
        modelview_urls['add'] = url_for(view_name + ".add")
        modelview_urls['edit'] = url_for(view_name + ".edit",pk="")
        return modelview_urls

    @expose('/api',methods=['GET'])
    @has_access_api
    @permission_name('list')
    def api(self):
        view_name = self.__class__.__name__
        api_urls = self._get_api_urls()
        modelview_urls = self._get_modelview_urls()

        #Collects the CRUD permissions
        can_show = self.appbuilder.sm.has_access('can_show',view_name)
        can_edit = self.appbuilder.sm.has_access('can_edit',view_name)
        can_add = self.appbuilder.sm.has_access('can_add',view_name)
        can_delete = self.appbuilder.sm.has_access('can_delete',view_name)

        #Prepares the form with the search fields make it JSON serializable
        form_fields = {}
        search_fields = {}
        dict_fields = self._filters.get_search_filters()
        form = self.search_form.refresh()
        for col in self.search_columns:
            form_fields[col] = form[col]()
            search_filters[col] = [as_unicode(flt.name) for flt in dict_filters[col]]

        ret_json = jsonify(can_show=can_show,
                can_add=can_add,
                can_edit=can_edit,
                can_delete=can_delete,
                label_columns=self._label_columns_json(),
                list_columns=self.list_columns,
                order_columns=self.order_columns,
                page_size=self.page_size,
                modelview_name=view_name,
                api_urls=api_urls,
                search_filters=search_filters,
                search_fields=form_fields,
                modelview_urls=modelview_urls)
        response = make_response(rel_json,200)
        response.headers['Content-Type'] = "application/json"
        return response

    @expose_api(name='read',url='/api/read',methods=['GET'])
    @has_access_api
    @permission_name('list')
    def api_read(self):

        #Get arguments for ordering
        if get_order_args().get(self.__class__.__name__):
            order_column,order_direction = get_order_args().get(self.__cllass__.__name__)
        else:
            order_column,order_direction = '',''
        page = get_page_args().get(self.__class__.__name__)
        page_size = get_page_size_args().get(self.__class__.__name__)
        get_filter_args(self._filters)
        joined_filters = self._filters.get_joined_filters(self._base_filters)
        count,lst = self.datamodel.query(joined_filters,order_column,order_direction,page=page,page_size=page_size)
        result = self.datamodel.get_values_json(lst,self.list_columns)
        pks = self.datamodel.get_keys(lst)
        ret_json = jsonify(label_columns=self._label_columns_json(),
                list_columns=self.list_columns,
                order_columns=self.order_columns,
                page=page,
                page_size=page_size,
                count=count,
                modelview_name=self.__class__.__name__,
                pks=pks,
                result=result)
        response = make_response(ret_json,200)
        response.headers['Content-Type'] = "application/json"
        return response

    @expose_api(name='get',url='/api/get/<pk>',methods=['GET'])
    @has_access_api
    @permission_name('show')
    def api_get(self,pk):

        item = self.datamodel.get(pk,self._base_filters)
        if not item:
            abort(404)
        _item = dict()
        for col in self.show_columns:
            _item[col] = str(getattr(item,col))

        ret_json = jsonify(pk=pk,
                label_columns=self._label_columns_json(),
                include_columns=self.show_columns,
                modelview_name=self.__class__.__name__,
                result=_item)
        response = make_response(ret_json,200)
        response.headers['Content-Type'] = "application/json"
        return response

    @expose_api(name='create',url='/api/create',methods=['POST'])
    @has_access_api
    @permission_name('create')
    def api_create(self):
        is_valid_form = True
        get_filter_args(self._filters)
        exclude_cols = self._filters.get_relation_cols()
        form = self.add_form.refresh()

        self._fill_form_exclude_cols(exclude_cols,form)
        if form.validate():
            item = self.datamodel.obj()
            form.populate_obj(item)
            self.pre_add(item)
            if self.datamodel.add(item):
                self.post_add(item)
                http_return_code = 200
            else:
                http_return_code = 500
        else:
            is_valid_form = False

        if is_valid_form:
            response = make_response(jsonify({'message':self.datamodel.message[0],
                'severity':'warning'}),http_return_code)
        else:
            response = make_response(jsonify({'message':'Invalid form','severity':'warning'}),500)
        return response

    @expose_api(name='update',url='/api/update/<pk>',methods=['PUT'])
    @has_access_api
    @permission_name('edit')
    def api_update(self,pk):
        is_valid_form = True
        get_filter_args(self._filters)
        exclude_cols = self._filters.get_relation_cols()

        item = self.datamodel.get(pk,self._base_filters)
        if not item:
            abort(404)
        pk = self.datamodel.get_pk_value(item)

        form = self.edit_form.refresh(request.form)
        self._fill_form_exclude_cols(exclude_cols,form)
        form._id = pk
        if form.validate():
            form.populate_obj(item)
            self.pre_update(item)
            if self.datamodel.edit(item):
                self.post_update(item)
                http_return_code = 200
            else:
                http_return_code = 500
        else:
            is_valid_form = False
        if is_valid_form:
            response = make_response(jsonify({'message':self.datamodel.message[0],'severity':self.datamodel.message[1]}),http_return_code)
        else:
            response = make_response(jsonify({'message':'Invalid form','severity':'warning'}),500)
        return response

    @expose_api(name='delete',url='/api/delete/<pk>',methods=['DELETE'])
    @has_access_api
    @permission_name('delete')
    def api_delete(self,pk):
        item = self.datamodel.get(pk,self._base_filters)
        if not item:
            abort(404)
        self.pre_delete(item)
        if self.datamodel.delete(item):
            self.post_delete(item)
            http_return_code = 200
        else:
            http_return_code = 500
        response = make_response(jsonify({'message':self.datamodel.message[0],'severity':self.datamodel.message[1]}),http_return_code)
        response.headers['Content-Type'] = "application/json"
        return response

    def _get_related_column_data(self,col_name,filters):
        rel_datamodel = self.datamodel.get_related_interface(col_name)
        _filters = rel_datamodel.get_filters(rel_datamodel.get_search_columns_list())
        get_filter_args(_filters)
        if filters:
            filters = _filters.add_filter_list(filters)
        else:
            filters = _filters
        result = rel_datamodel.query(filters)[1]
        rel_list = list()
        for item in result:
            pk = rel_datamodel.get_pk_value(item)
            ret_list.append({'id':int(pk),'text':str(item)})
        ret_json = json.dumps(ret_list)
        return ret_json

    @expose_api(name='column_add',url='/api/column/add/<col_name>',methods=['GET'])
    @has_access_api
    @permission_name('add')
    def api_column_add(self,col_name):

        filter_rel_fields = None
        if self.add_form_query_rel_fields:
            filter_rel_fields = self.add_form_query_rel_fields.get(col_name)
        ret_json = self._get_related_column_data(col_name,filter_rel_fields)
        response = make_response(ret_json,200)
        response.headers['Content-Type'] = "application/json"
        return response

    @expose_api(name='column_edit',url='/api/column/edit/<col_name>',methods=['GET'])
    @has_access_api
    @permission_name('edit')
    def api_column_edit(self,col_name):

        filter_rel_fields = None
        if self.edit_form_query_rel_fields:
            filter_rel_fields = self.edit_form_query_rel_fields
        ret_json = self._get_related_column_data(col_name,filter_rel_fields)
        response = make_response(ret_json,200)
        response.headers['Content-Type']="application/json"
        return response

    @expose_api(name='readvalues',url='/api/readvalues',methods=['GET'])
    @has_access_api
    @permission_name('list')
    def api_readvalues(self):

        if get_order_args().get(self.__class__.__name__):
            order_column,order_direction = get_order_args().get(self.__class__.__name__)
        else:
            order_column,order_direction = '',''

        get_filter_args(self._filters)
        joined_filters = self._filters.get_joined_filters(self._base_filters)
        count,result = self.datamodel.query(joined_filters,order_column,order_direction)

        ret_list = list()
        for item in result:
            pk = self.datamodel.get_pk_value(item)
            ret_list.append({'id':int(pk),'text':str(item)})

        ret_json = json.dumps(ret_list)
        response = make_response(ret_json,200)
        response.headers['Content-Type'] = "application/json"
        return response


class ModelView(RestCRUDView):

    def __init__(self,**kwargs):
        super(ModelView,self).__init__(**kwargs)

    def post_add_redirect(self):
        """Override this function to control the redirect after add endpoint is called."""
        return redirect(self.get_redirect())

    def post_edit_redirect(self):
        return redirect(self.get_redirect())

    def post_delete_redirect(self):
        return redirect(self.get_redirect())

    """
    ---------------
        LIST SHOW ADD EDIT DELETE ---------------
    """

    @expose('/list/')
    @has_access
    def list(self):

        widgets = self._list()
        return self.render_template(self.list_template,title=self.list_title,widgets=widgets)

    @expose('/show/<pk>',methods=['GET'])
    @has_access
    def show(self,pk):
        widgets = self._show(pk)
        return self.render_template(self.show_template,pk=pk,title=self.show_title,
                widgets=widgets,related_views=self._related_views)

    @expose('/add',methods=['GET','POST'])
    @has_access
    def add(self):
        widget = self._add()
        if not widget:
            return self.post_add_redirect()
        else:
            return self.render_template(self.add_template,title=self.add_title,widgets=widget)

    @expose('/edit/<pk>',methods=['GET','POST'])
    @has_access
    def edit(self,pk):
        widgets = self._edit(pk)
        if not widgets:
            return self.post_edit_redirect()
        else:
            return self.render_template(self.edit_template,title=self.edit_title,
                    widgets=widgets,related_views=self._related_views)

    @expose('/delete/<pk>')
    @has_access
    def delete(self,pk):
        self._delete(pk)
        return self.post_delete_redirect()

    @expose('/download/<string:filename>')
    @has_access
    def download(self,filename):
        return send_file(self.appbuilder.app.config['UPLOAD_FOLDER'] + filename,
                attachment_filename=uuid_originalname(filename),as_attachment=True)

    @expose('/action/<string:name>/<pk>',methods=['GET'])
    def action(self,name,pk):
        if self.appbuilder.sm.has_access(name,self.__class__.__name__):
            action = self.actions.get(name)
            return action.func(self.datamodel.get(pk))
        else:
            flash(as_unicode(FLAMSG_ERR_SEC_ACCESS_DENIED),"danger")
            return redirect('.')

    @expose('/action_post',methods=['POST'])
    def action_post(self):
        name = request.form['action']
        pks = request.form.getlist('rowid')
        if self.appbuilder.sm.has_access(name,self.__class__.__name__):
            action = self.actions.get(name)
            items = [self.datamodel.get(pk) for pk in pks]
            return action.func(items)
        else:
            flash(as_unicode(FLAMSG_ERR_SEC_ACCESS_DENIED),"danger")
            return redirect('.')


class MasterDetailView(BaseCRUDView):
    """
            Implements behaviour for controlling two CRUD views
            linked by PK and FK, in a master/detail type with
           two lists.

            Master view will behave like a left menu::
                class DetailView(ModelView):
                     datamodel = SQLAInterface(DetailTable, db.session)
                class MasterView(MasterDetailView):
                     datamodel = SQLAInterface(MasterTable, db.session)
                     related_views = [DetailView]
    """
    list_template = 'appbuilder/general/model/lef_master_detail.html'
    list_widget = ListMasterWidget
    master_div_width = 2
    """ set to configure bootstrap class for master grid size"""

    @expose('/list')
    @expose('/list/<pk>')
    @has_access
    def list(self,pk=None):
        pages = get_page_args()
        page_size = get_page_size_args()
        orders = get_order_args()

        widgets = self._list()
        if pk:
            item = self.datamodel.get(pk)
            widgets = self._get_related_views_widgets(item,orders=orders,
                    pages=pages,page_sizes=page_sizes,widgets=widgets)
            related_views = self._related_views
        else:
            related_views = []

        return self.render_template(self.list_template,
                title=self.list_title,
                widgets=widgets,
                related_views=related_views,
                master_div_width=self.master_div_width)
