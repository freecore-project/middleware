import shlex


def ssh_remote_path(remote, path):
    # shlex.quote() supplies the shell layer. Wrapping its result in another pair of quotes makes the quotes
    # literal to rsync and turns an absolute remote path into a relative path below the remote user's home.
    return f'{remote}:{shlex.quote(path)}'
