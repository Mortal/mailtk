'''
TODO: Use RFC 4551 MODSEQ for fast searches?
'''
import os
import re
import queue
import asyncio
import threading

from mailtk.data import Mailbox, MessageBase, Flag, namedtuple

from imapclient import IMAPClient
import email
import imapclient
from mailtk.util import decode_any_header
from mailtk.accounts.base import AccountBase, AccountData, Pending


asyncio.Event


class _ThreadMessage(namedtuple.abc):
    _fields = (
        'flag', 'size', 'date', 'from_', 'to', 'cc', 'subject',
        'message_id', 'references', 'in_reply_to')


class MailboxImap(Mailbox):
    _fields = 'flags'

    @property
    def path(self):
        return self.key


def imap_unescape(v):
    if v.startswith('"'):
        mo = re.match(r'^"(?:[^"\\]|\\")*"$', v)
        assert mo
        return v[1:-1].replace('\\"', '"')
    return v


class ImapAccount(AccountBase):
    @classmethod
    async def initialize(cls, loop, host, port, username, password, ssl=False):
        # TODO: STARTTLS support?
        imap = cls(loop, host, int(port), bool(ssl))
        await imap.connect()
        await imap.backend.login(username, password)
        return imap

    def __init__(self, loop, host, port, ssl, account_data: AccountData):
        self.backend = ImapBackend(loop, host, port, ssl)
        self.frontend = account_data
        self._selected_folder = None
        self._uidvalidity_counter = 0  # Used if server doesn't send UIDVALIDITY

    async def connect(self):
        await self.backend.connect()

    async def disconnect(self):
        await self.backend.disconnect()

    async def capabilities(self):
        return await self.backend.capabilities()

    def _check_code(self, result):
        code, data = result
        if code != 'OK':
            assert len(data) == 1
            raise Exception(data[0].decode())
        return data

    async def list_folders(self):
        add_inbox = True
        existing_folders = []
        for flags, delimiter, path in await self.backend.list_folders():
            delimiter = (delimiter or b'').decode()
            parent, sep, name = path.rpartition(delimiter)
            m = MailboxImap(
                Mailbox(name, path, parent or None), flags)
            self.frontend.set_folder(m)
            existing_folders.append(path)
            if name.upper() == 'INBOX':
                add_inbox = False
        if add_inbox:
            print("Inserting INBOX")
            # TODO what is the 'flags' of INBOX?
            m = MailboxImap(
                Mailbox('INBOX', 'INBOX', None), None)
            self.frontend.set_folder(m)
            existing_folders.append('INBOX')
        self.frontend.set_folder_set(existing_folders)

    async def _select_folder(self, path):
        if self._selected_folder == path:
            return self._selected_response
        self._selected_response = await self.backend.select_folder(path)
        self._selected_folder = path
        return self._selected_response

    def _parse_flags(self, imap_flags):
        if b'\\Answered' in imap_flags:
            return Flag.replied
        elif b'\\Seen' in imap_flags:
            return Flag.read
        elif b'\\Recent' in imap_flags:
            return Flag.new
        else:
            return Flag.unread

    def _parse_search(self, message_value):
        message_value.pop(b'SEQ', None)
        flag = self._parse_flags(message_value.pop(b'FLAGS'))
        size = message_value.pop(b'RFC822.SIZE')
        (k, message_bytes), = message_value.items()
        assert k.startswith(b'BODY')
        mime = email.message_from_bytes(message_bytes)

        def header(k, d=None):
            v = mime[k]
            return d if v is None else str(decode_any_header(v))

        return _ThreadMessage(
            flag=flag,
            size=size,
            date=email.utils.parsedate_to_datetime(
                header('Date')),
            from_=header('From'),
            to=header('To'),
            cc=header('Cc'),
            subject=header('Subject'),
            message_id=header('Message-ID'),
            references=header('References', '').split(),
            in_reply_to=header('In-Reply-To', '').split(),
        )

    def _get_fake_uidvalidity(self):
        self._uidvalidity_counter += 1
        return 'fake_%s' % self._uidvalidity_counter

    def _convert_message(self, o: _ThreadMessage, key, parent_key):
        folder = key[0]
        assert isinstance(folder, MailboxImap)
        v = MessageBase(
            flag=o.flag,
            size=o.size,
            date=o.date,
            sender=o.from_,
            recipients=', '.join(filter(None, (o.to, o.cc))),
            subject=o.subject,
            excerpt='',
            message_id=o.message_id,
            folder_key=folder.key,
            key=key,
            parent_key=parent_key,
        )
        return v

    async def list_messages(self, mailbox: MailboxImap):
        # TODO: Sorting
        assert isinstance(mailbox, MailboxImap)
        path = mailbox.path

        select_response = await self._select_folder(path)
        n_messages = select_response[b'EXISTS']
        if n_messages == 0:
            return []
        # flags = select_response[b'FLAGS']
        # recent = select_response[b'RECENT']
        real_uidvalidity = select_response.get(b'UIDVALIDITY')
        if real_uidvalidity is None:
            uidvalidity = self._get_fake_uidvalidity()
            # gen_uidvalidity = uidvalidity
        else:
            uidvalidity = real_uidvalidity

        # TODO: Use MODSEQ in SEARCH
        uids = await self.backend.search()
        params = [
            'FLAGS', 'RFC822.SIZE',
            'BODY.PEEK[HEADER.FIELDS (Date From To Cc Subject ' +
            'Message-ID References In-Reply-To)]']
        block_size = 4
        children = {}
        message_ids = {}  # map RFC822.Message-Id to MessageBase.key
        for i in range(0, len(uids), block_size):
            j = min(i+block_size, len(uids))
            data = await self.backend.fetch(uids[i:j], params)
            for uid in uids[i:j]:
                key = (mailbox, uidvalidity, uid)
                m = self._parse_search(data.pop(uid))
                if m.in_reply_to:
                    assert isinstance(m.in_reply_to, list)
                    parent_message_id = m.in_reply_to[0]
                    try:
                        parent_key = message_ids[parent_message_id]
                    except KeyError:
                        parent_key = Pending
                        children.setdefault(parent_message_id, []).append(key)
                else:
                    parent_key = None
                self.frontend.set_message(self._convert_message(
                    m, key, parent_key))
                for c in children.pop(m.message_id, ()):
                    self.frontend.set_message_parent(c, key)
                message_ids[m.message_id] = key
            if data:
                raise Exception("unhandled FETCH data: %r" % (data,))
        for parent_message_id, child_list in children.items():
            for c in children:
                self.frontend.set_message_parent(c, None)
        self.frontend.set_message_set(list(message_ids.values()))

    async def fetch_message(self, message: MessageBase):
        assert isinstance(message, MessageBase), type(message)
        folder, uidvalidity, uid = message.key
        select_response = await self._select_folder(folder.path)
        folder_uidvalidity = select_response.get(b'UIDVALIDITY')
        if folder_uidvalidity not in (None, uidvalidity):
            raise NotImplementedError(
                'fetch_message: UIDVALIDITY changed!')
        params = ['RFC822']
        data, = (await self.backend.fetch([uid], params)).values()
        self.frontend.set_message_data(message.key, data[b'RFC822'])


class ImapBackend:
    BREAK = object()
    NOOP = object()

    def __init__(self, loop, host, port, ssl):
        self._loop = loop
        self._host = host
        self._port = port
        self._ssl = ssl
        self._command_queue = queue.Queue()
        self._response_queue = queue.Queue()
        self._ready_r, self._ready_w = os.pipe()
        loop.add_reader(self._ready_r, self._ready)
        self._ready = threading.Event()
        self._thread = threading.Thread(None, self._run)
        self._breaking = False

    async def connect(self):
        self._thread.start()

    async def disconnect(self):
        await self.logout()
        await self._call(self.BREAK)
        self._thread.join()

    async def _call(self, method, *args):
        if self._breaking:
            raise Exception('connection is closing')
        future = asyncio.Future(loop=self._loop)
        self._command_queue.put_nowait((future, method, args))
        if method is self.BREAK:
            self._breaking = True
        result = await future
        if isinstance(result, Exception):
            raise result
        return result

    def _run(self):
        # Run commands in thread
        if self._ssl:
            kwargs = dict(
                ssl_context=imapclient.create_default_context())
        else:
            kwargs = {}
        try:
            conn = IMAPClient(self._host, self._port, ssl=self._ssl, **kwargs)
        except Exception as exn:
            future, method, args = self._command_queue.get()
            self._response_queue.put((future, exn))
            self._command_queue.task_done()
            os.write(self._ready_w, b'x')
            return
        try:
            while True:
                future, method, args = self._command_queue.get()
                if method is self.BREAK:
                    break
                elif method is self.NOOP:
                    result = None
                else:
                    # TODO check if future is cancelled
                    try:
                        result = getattr(conn, method)(*args)
                    except Exception as exn:
                        result = exn
                self._response_queue.put((future, result))
                self._command_queue.task_done()
                os.write(self._ready_w, b'x')
        finally:
            conn.shutdown()

        assert method is self.BREAK
        self._response_queue.put((future, None))
        self._command_queue.task_done()
        os.write(self._ready_w, b'x')

    def _ready(self):
        os.read(self._ready_r, 1)
        future, result = self._response_queue.get_nowait()
        if not future.cancelled():
            future.set_result(result)
        self._response_queue.task_done()

    # The following methods were generated by gen-imap.py
    async def add_flags(self, messages, flags, silent=False):
        'Add *flags* to *messages* in the currently selected folder.'
        return await self._call('add_flags', messages, flags, silent)

    async def add_gmail_labels(self, messages, labels, silent=False):
        'Add *labels* to *messages* in the currently selected folder.'
        return await self._call('add_gmail_labels', messages, labels, silent)

    async def append(self, folder, msg, flags=(), msg_time=None):
        'Append a message to *folder*.'
        return await self._call('append', folder, msg, flags, msg_time)

    async def capabilities(self):
        'Returns the server capability list.'
        return await self._call('capabilities')

    async def close_folder(self):
        'Close the currently selected folder, returning the server'
        return await self._call('close_folder')

    async def copy(self, messages, folder):
        'Copy one or more messages from the current folder to'
        return await self._call('copy', messages, folder)

    async def create_folder(self, folder):
        'Create *folder* on the server returning the server response string.'
        return await self._call('create_folder', folder)

    async def delete_folder(self, folder):
        'Delete *folder* on the server returning the server response string.'
        return await self._call('delete_folder', folder)

    async def delete_messages(self, messages, silent=False):
        'Delete one or more *messages* from the currently selected'
        return await self._call('delete_messages', messages, silent)

    async def expunge(self):
        'Remove any messages from the currently selected folder that'
        return await self._call('expunge')

    async def fetch(self, messages, data, modifiers=None):
        'Retrieve selected *data* associated with one or more'
        return await self._call('fetch', messages, data, modifiers)

    async def folder_exists(self, folder):
        'Return ``True`` if *folder* exists on the server.'
        return await self._call('folder_exists', folder)

    async def folder_status(self, folder, what=None):
        'Return the status of *folder*.'
        return await self._call('folder_status', folder, what)

    async def get_flags(self, messages):
        'Return the flags set for each message in *messages* from'
        return await self._call('get_flags', messages)

    async def get_gmail_labels(self, messages):
        'Return the label set for each message in *messages* in the'
        return await self._call('get_gmail_labels', messages)

    async def getacl(self, folder):
        'Returns a list of ``(who, acl)`` tuples describing the'
        return await self._call('getacl', folder)

    async def gmail_search(self, query, charset='UTF-8'):
        "Search using Gmail's X-GM-RAW attribute."
        return await self._call('gmail_search', query, charset)

    async def has_capability(self, capability):
        'Return ``True`` if the IMAP server has the given *capability*.'
        return await self._call('has_capability', capability)

    async def id_(self, parameters=None):
        'Issue the ID command, returning a dict of server implementation'
        return await self._call('id_', parameters)

    async def idle(self):
        'Put the server into IDLE mode.'
        return await self._call('idle')

    async def idle_check(self, timeout=None):
        'Check for any IDLE responses sent by the server.'
        return await self._call('idle_check', timeout)

    async def idle_done(self):
        'Take the server out of IDLE mode.'
        return await self._call('idle_done')

    async def list_folders(self, directory='', pattern='*'):
        'Get a listing of folders on the server as a list of'
        return await self._call('list_folders', directory, pattern)

    async def list_sub_folders(self, directory='', pattern='*'):
        'Return a list of subscribed folders on the server as'
        return await self._call('list_sub_folders', directory, pattern)

    async def login(self, username, password):
        'Login using *username* and *password*, returning the'
        return await self._call('login', username, password)

    async def logout(self):
        'Logout, returning the server response.'
        return await self._call('logout')

    async def namespace(self):
        'Return the namespace for the account as a (personal, other,'
        return await self._call('namespace')

    async def noop(self):
        'Execute the NOOP command.'
        return await self._call('noop')

    async def oauth2_login(self, user, access_token, mech='XOAUTH2', vendor=None):
        'Authenticate using the OAUTH2 method.'
        return await self._call(
            'oauth2_login', user, access_token, mech, vendor)

    async def oauth_login(self, url, oauth_token, oauth_token_secret, consumer_key='anonymous', consumer_secret='anonymous'):
        'Authenticate using the OAUTH method.'
        return await self._call(
            'oauth_login', url, oauth_token, oauth_token_secret, consumer_key, consumer_secret)

    async def plain_login(self, identity, password, authorization_identity=None):
        'Authenticate using the PLAIN method (requires server support).'
        return await self._call(
            'plain_login', identity, password, authorization_identity)

    async def remove_flags(self, messages, flags, silent=False):
        'Remove one or more *flags* from *messages* in the currently'
        return await self._call('remove_flags', messages, flags, silent)

    async def remove_gmail_labels(self, messages, labels, silent=False):
        'Remove one or more *labels* from *messages* in the'
        return await self._call(
            'remove_gmail_labels', messages, labels, silent)

    async def rename_folder(self, old_name, new_name):
        'Change the name of a folder on the server.'
        return await self._call('rename_folder', old_name, new_name)

    async def search(self, criteria='ALL', charset=None):
        'Return a list of messages ids from the currently selected'
        return await self._call('search', criteria, charset)

    async def select_folder(self, folder, readonly=False):
        'Set the current folder on the server.'
        return await self._call('select_folder', folder, readonly)

    async def set_flags(self, messages, flags, silent=False):
        'Set the *flags* for *messages* in the currently selected'
        return await self._call('set_flags', messages, flags, silent)

    async def set_gmail_labels(self, messages, labels, silent=False):
        'Set the *labels* for *messages* in the currently selected'
        return await self._call('set_gmail_labels', messages, labels, silent)

    async def setacl(self, folder, who, what):
        'Set an ACL (*what*) for user (*who*) for a folder.'
        return await self._call('setacl', folder, who, what)

    async def shutdown(self):
        'Close the connection to the IMAP server (without logging out)'
        return await self._call('shutdown')

    async def sort(self, sort_criteria, criteria='ALL', charset='UTF-8'):
        'Return a list of message ids from the currently selected'
        return await self._call('sort', sort_criteria, criteria, charset)

    async def starttls(self, ssl_context=None):
        'Switch to an SSL encrypted connection by sending a STARTTLS command.'
        return await self._call('starttls', ssl_context)

    async def subscribe_folder(self, folder):
        'Subscribe to *folder*, returning the server response string.'
        return await self._call('subscribe_folder', folder)

    async def thread(self, algorithm='REFERENCES', criteria='ALL', charset='UTF-8'):
        'Return a list of messages threads from the currently'
        return await self._call('thread', algorithm, criteria, charset)

    async def unsubscribe_folder(self, folder):
        'Unsubscribe to *folder*, returning the server response string.'
        return await self._call('unsubscribe_folder', folder)

    async def xlist_folders(self, directory='', pattern='*'):
        'Execute the XLIST command, returning ``(flags, delimiter,'
        return await self._call('xlist_folders', directory, pattern)
    # End generated methods
