#!/usr/bin/env python3


from imapclient import IMAPClient
import inspect


def main():
    first = True
    print('    # The following methods were generated by gen-imap.py')
    for k in dir(IMAPClient):
        if k.startswith('_'):
            continue
        v = getattr(IMAPClient, k)
        if isinstance(v, (property, type)):
            continue
        d = v.__doc__
        sig = inspect.signature(v)
        params = str(sig)
        assert params.startswith('(self')
        params = params[5:]
        if not first:
            print('')
        first = False
        print('    async def %s(self%s:' % (k, params))
        if d:
            if '.' in d:
                d = d[:d.index('.')+1]
            if '\n' in d:
                d = d[:d.index('\n')]
            print('        %r' % d)
        args = ''.join(', %s%s' % ('*' if v.kind == 2 else '', k)
                       for k, v in sig.parameters.items()
                       if k != 'self')
        line = '        return await self._call(%r%s)' % (k, args)
        if len(line) >= 80:
            line = ('        return await self._call(\n' +
                    '            %r%s)' % (k, args))
        print(line)
    print('    # End generated methods')


if __name__ == '__main__':
    main()
