from flask_babel import lazy_gettext


"""
    All constants and messages definitions go here

    Log messages obey the following rule:

        lOGMSG_<SEV>_<MODULE>_<NAME>
            <SEV>:-INF|DEB|WAR|ERR
            <MODULE>:-SEC

    Flash messages obey the following rule:

        FLAMSG_<SEV>_<MODULE>_<NAME>
            <SEV>:-INF|DEB|WAR|ERR
            <MODULE>:-SEC
"""


LOGMSG_ERR_SEC_ACCESS_DENIED = "Access is Denied for:{0} on:{1}"
"""Acess denied log message,format with user and view/resource"""
LOGMSG_WAR_SEC_LOGIN_FAILED = "Login Failed for user:{0}"
LOGMSG_ERR_SEC_CREATE_DB = "DB Createion and initialization failed:{0}"
"""security models creation fails,format with error message"""
LOGMSG_ERR_SEC_ADD_ROLE = "Add Role:{0}"
"""Error adding role,format with err message"""
LOGMSG_ERR_SEC_ADD_PERMISSION = "Add Permission:{0}"
LOGMSG_ERR_SEC_ADD_VIEWMENU = "Add View Menu Error:{0}"
LOGMSG_ERR_SEC_DEL_PERMISSION = "del Permission Error:{0}"
LOGMSG_ERR_SEC_ADD_PERMVIEW = "Creation of Permission View Error:{0}"
LOGMSG_ERR_SEC_DEL_PERMVIEW = "Remove Permission from View Error:{0}"
LOGMSG_ERR_SEC_ADD_PERMROLE = "Add Permission to Role Error:{0}"
LOGMSG_ERR_SEC_DEL_PERMROLE = "Remove Permission to Role Error:{0}"
LOGMSG_ERR_SEC_ADD_REGISTER_USER = "Add Register User Error:{0}"
LOGMSG_ERR_SEC_DEL_REGISTER_USER = "Remove Register User Error:{0}"
LOGMSG_ERR_SEC_NO_REGISTER_HASH = "Attempt to activate user with false hash:{0}"
LOGMSG_ERR_SEC_AUTH_LDAP = "LDAP Error {0}"
LOGMSG_ERR_SEC_ADD_USER = "Error adding new user to database.{0}"
LOGMSG_ERR_SEC_UPD_USER = "Error updating user to database.{0}"
LOGMSG_WAR_SEC_NO_USER = "No user yet created,use fabmanager command to do it."
LOGMSG_WAR_SEC_NOLDAP_OBJ = "User self registration failed no LDAP object found for:{0}"
LOGMSG_INF_SEC_ADD_PERMVIEW = "Created Permission View:{0}"
LOGMSG_INF_SEC_DEL_PERMVIEW = "Removed Permission View:{0} on {1}"
LOGMSG_INF_SEC_ADD_PERMROLE = "Add Permission {0} to role {1}"
LOGMSG_INF_SEC_DEL_PERMROLE = "Removed Permission {0} to role {1}"
LOGMSG_INF_SEC_ADD_ROLE = "Inserted Role:{0}"
LOGMSG_INF_SEC_NO_DB = "Security DB not found Creating all Models from Base"
LOGMSG_INF_SEC_ADD_DB = "Security DB Created"
LOGMSG_INF_SEC_ADD_USER = "Added user {0}"
LOGMSG_INF_SEC_UPD_USER = "Updated user {0}"

LOGMSG_INF_FAB_ADDON_ADDED = "Registered AddOn:{0}"
LOGMSG_ERR_FAB_ADDON_IMPORT = "An error occurred when importing declared addon {0}:{1}"
LOGMSG_ERR_FAB_ADDON_PROCESS = "An error occurred when processing declared addon {0}:{1}"

LOGMSG_ERR_FAB_ADD_PERMISSION_MENU = "Add Permission on Menu error:{0}"
LOGMSG_ERR_FAB_ADD_PERMISSION_VIEW = "Add Permisson on View Error:{0}"
LOGMSG_ERR_DBI_ADD_GENERIC = "Add record error:{0}"
LOGMSG_ERR_DBI_EDIT_GENERIC = "Edit record error:{0}"
LOGMSG_ERR_DBI_DEL_GENERIC = "Delete record error:{0}"
LOGMSG_WAR_DBI_AVG_ZERODIV = "Zero division on aggregate_avg"

LOGMSG_WAR_FAB_VIEW_EXISTS = "View already exists {0} ignoring"
LOGMSG_WAR_DBI_ADD_INTEGRITY = "Add record integrity error:{0}"
LOGMSG_WAR_DBI_EDIT_INTEGRITY = "Edit record integrity error:{0}"
LOGMSG_WAR_DBI_DEL_INTEGRITY = "Delet record integrity error:{0}"

LOGMSG_INF_FAB_ADD_VIEW = "Registeing class {0} on menu {1}"


FLAMSG_ERR_SEC_ACCESS_DENIED = lazy_gettext("Access is Denied")



PERMISSION_PREFIX = 'can_'
"""Prefix to concatenated to permission names,and inserted in the backend"""



AUTH_OID = 0
AUTH_DB = 1
AUTH_LDAP = 2
AUTH_REMOTE_USER = 3
AUTH_OAUTH = 4
""" Constants for supported authentication types """


