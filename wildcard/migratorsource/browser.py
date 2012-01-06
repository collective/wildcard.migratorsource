from AccessControl import getSecurityManager
from Products.CMFCore.utils import getToolByName
from wildcard.migrator import mjson as json
from Products.Five import BrowserView
from wildcard.migrator import scan
from wildcard.migrator.utils import getMigratorFromRequest
from AccessControl.SecurityManagement import newSecurityManager
from AccessControl.User import UnrestrictedUser as BaseUnrestrictedUser
from wildcard.migrator.utils import safeTraverse

scan()


import logging
logger = logging.getLogger('wildcard.migrator')


class UnrestrictedUser(BaseUnrestrictedUser):
    """Unrestricted user that still has an id.
    """
    def getId(self):
        """Return the ID of the user.
        """
        return self.getUserName()


class Exporter(BrowserView):

    def __call__(self):

        # give admin privs no matter what
        # XXX remember, this is not safe to have on a
        # production site!
        sm = getSecurityManager()
        tmp_user = UnrestrictedUser(sm.getUser().getId(), '', ['Manager'],
            '')
        acl = getToolByName(self.context, 'acl_users')
        tmp_user = tmp_user.__of__(acl)
        newSecurityManager(None, tmp_user)
        migrator = getMigratorFromRequest(self.request)

        self.request.response.setHeader('Content-Type', 'application/json')
        try:
            path = '/'.join(migrator.obj.getPhysicalPath())
        except:
            path = repr(migrator.obj)
        logger.info('Running %s for %s' % (migrator.title, path))
        data = migrator.get()
        return json.dumps(data)


class ServeFileField(BrowserView):

    def __call__(self):
        field = self.request.get('field')
        context = safeTraverse(self.context, self.request.get('path'))
        field = context.getField(field)
        filename = field.getFilename(context)
        if not filename:
            filename = context.getId()
        resp = self.request.response
        resp.setHeader('filename', filename)
        resp.setHeader('Content-type', field.getContentType(context))
        return field.download(context)
