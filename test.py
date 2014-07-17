import qdb
from qdb import Qdb

def main():
    db = Qdb(uuid_fn=lambda: 'qdb',redirect_stdout=False)
    db.set_break('test.py', 9)
    db.set_trace(stop=False)
    test = 10
    print 'hi'
    f()
    print 'back in main'


def f():
    print 'I am in f'
    g = 3
    print g


if __name__ == '__main__':
    main()
