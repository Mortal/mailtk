'''
Note that subclassing of namedtuple works in a particular duck-typy fashion.
The base class Mailbox is subclassed as MailboxAccount and MailboxImap.
The IMAP account returns MailboxImap instances which are wrapped into
MailboxAccount instances by the controller, and the controller unwraps the
MailboxAccount into a MailboxImap when passing back to the account.
This works even though MailboxAccount subclasses Mailbox instead of
MailboxImap.
'''


from enum import Enum
from mailtk.namedtuple_with_abc import namedtuple


try:
    # Don't redefine when reloading mailtk/data.py
    Pending
except NameError:
    class Pending:
        '''
        Special value indicating that a field will be retrieved from a remote
        server.
        '''
        def __bool__(self):
            return False

        def __str__(self):
            return '<pending>'

        def __repr__(self):
            return '%s.%s' % (self.__module__, self.__class__.__name__)

    Pending = Pending()


class Flag(Enum):
    read = 'read'
    unread = 'unread'
    new = 'new'
    replied = 'replied'
    forwarded = 'forwarded'


class MessageBase(namedtuple.abc):
    '''
    flag: Flag
    size: int
    date: datetime.datetime
    sender: ?address
    recipients: list of ?address
    subject: str
    excerpt: str
    - Short substring of body text
    message_id: str
    - RFC822.Message-Id header
    key: hashable, account-specific
    parent_key: hashable, account-specific
    '''
    _fields = ('flag', 'size', 'date', 'sender', 'recipients', 'subject',
               'excerpt', 'message_id', 'key', 'parent_key')


class Folder(namedtuple.abc):
    _fields = 'name key parent_key'


class AccountData:
    pass


class SimpleAccountData(AccountData):
    def __init__(self, account_key):
        self._folders = {}
        self._messages = {}
        self._message_data = {}

    def set_folder(self, folder: Folder):
        self._folders[folder.key] = folder

    def set_folder_set(self, keys):
        stale = set(self._folders.keys()) - set(keys)
        for o in stale:
            del self._folders[o]

    def set_message(self, message: MessageBase):
        self._messages[message.key] = message

    def set_message_set(self, keys):
        stale = set(self._messages.keys()) - set(keys)
        for o in stale:
            del self._messages[o]
        stale = set(self._message_data.keys()) - set(keys)
        for o in stale:
            del self._message_data[o]

    def set_message_data(self, message_key, message_data):
        self._message_data[message_key] = message_data
