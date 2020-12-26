class CertifireError(Exception):
    pass

class DuplicateError(CertifireError):
    def __init__(self, key):
        self.key = key

    def __str__(self):
        return repr("Duplicate found! Could not create: {0}".format(self.key))

class AttrNotFound(CertifireError):
    def __init__(self, field):
        self.field = field

    def __str__(self):
        return repr("The field '{0}' is not sortable or filterable".format(self.field))

class UnknownProvider(CertifireError):
    pass

class PluginError(CertifireError):
    pass