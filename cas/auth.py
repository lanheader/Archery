from django.conf import settings
from django.contrib.auth.models import User
from django_cas_ng.backends import CASBackend

from common.auth import init_user
from common.config import SysConfig


class CASAuthenticationBackend(CASBackend):
    def get_user_info_ldap(self, user: User) -> User or None:
        """
        If CAS uses LDAP as the database, it can read user information from LDAP.
        Using the django_auth_ldap module to search for LDAP user information
        """
        from django_auth_ldap.backend import LDAPBackend

        ldap_backend = LDAPBackend()
        try:
            ldap_user = ldap_backend.populate_user(user.username)
            if ldap_user is None:
                return None
            sys_config = SysConfig()
            # Retrieve field information based on the LDAP attribute map.
            mail = settings.AUTH_LDAP_USER_ATTR_MAP["email"]
            display = settings.AUTH_LDAP_USER_ATTR_MAP["display"]
            user.email = ldap_user.ldap_user.attrs[mail][0]
            user.display = ldap_user.ldap_user.attrs[display][0]
            # If the Feishu app ID has been configured, query the user ID.
            if sys_config.get("feishu_appid"):
                user = self.get_user_info_feishu(user)
            return user
        except Exception:
            return None

    def get_user_info_feishu(self, user: User) -> User or None:
        """
        If a Feishu token is configured, the user_id can be obtained from Feishu,
        and the feishu_open_id of the user can be assigned a value.
        """
        from common.utils.feishu_api_new import FSMessage

        try:
            user.feishu_open_id = FSMessage().get_user_id(user.email)
            return user
        except Exception:
            return None

    def configure_user(self, user: User):
        """
        This function calls this method to provide supplementary information
        after CAS verification is completed.
        """
        if not user.email and settings.ENABLE_LDAP_DATA_COMPLETION:
            try:
                if not self.get_user_info_ldap(user):
                    raise
                init_user(user)
            except Exception:
                #  当飞书请求失败时，返回  None
                return None
