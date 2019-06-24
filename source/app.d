/**
 *  Porting kazuho/jailing in D.
 *  jailing is minimalistic chroot jail builder/runner for Linux
 *
 * Example:
 *   $ mkdir foo
 *   $ sudo jailing --root=$PWD/foo bash
 *
 */

import core.stdc.stdlib;
import core.sys.posix.sys.stat : chmod;
import std.algorithm : findSplit, splitter;
import std.conv : octal;
import std.exception : errnoEnforce;
import std.file;
import std.getopt;
import std.path : buildPath, isAbsolute;
import std.process;
import std.regex;
import std.stdio;
import std.string : toStringz;
import std.typecons : Yes;

version (linux):

extern (C)
{
    // see `man 2 chroot`.
    int chroot(const char* path);
}

immutable NEWDIRS = [
    "etc",
    "run",
    "usr",
    "var/log"
    ];
immutable BINDDIRS = [
    "bin",
    "etc/alternatives",
    "etc/pki/tls/certs",
    "etc/pki/ca-trust",
    "etc/ssl/certs",
    "lib",
    "lib64",
    "sbin",
    "usr/bin",
    "usr/include",
    "usr/lib",
    "usr/lib64",
    "usr/libexec",
    "usr/sbin",
    "usr/share",
    "usr/src"
    ];
immutable TEMPDIRS = ["tmp", "run/lock", "var/tmp"];
immutable COPYFILES = [
    "etc/group",
    "etc/passwd",
    "etc/resolv.conf",
    "etc/hosts"
    ];

void usage(Option[] options)
{
    defaultGetoptPrinter(
`jailing - a minimalistic chroot jail builder/runner for Linux, port to D.

** Examples:

$ # create and/or enter the jail, and optionally run the command
$ jailing --root=/path/to/chroot/jail [cmd ...]
`, options);
}

bool isEmptyDir(string dir)
{
    foreach (string name; dirEntries(dir, SpanMode.breadth))
        if (name != "." && name != "..")
            return false;
    return true;
}

void bindCustom(string root, string dir, bool readonly)
{
    const arr = dir.findSplit(":");
    const src = arr[0];
    const dest = !arr[2].length ? src : arr[2];

    if (!(src.isAbsolute && dest.isAbsolute))
        assert(false, "paths of `--bind=src-path[:dest-path]` option be absolute");
    if (isEmptyDir(src))
        executeShell("touch " ~ src ~ "/.jailing.keep");
    immutable destPath = buildPath(root, dest);
    mkdirRecurse(destPath);
    if (isEmptyDir(destPath))
    {
        executeShell("mount --bind " ~ src ~ " " ~ buildPath(root, dest));
        if (readonly)
            executeShell("mount -o remount,ro,bind " ~ buildPath(root, dest));
    }
}

void dropCapabilities()
{
    import core.sys.linux.sys.prctl;

    bool[size_t] KEEP_CAPS = [
        6  /* CAP_SETGID */: true,
        7  /* CAP_SETUID */: true,
        10 /* CAP_NET_BIND_SERVICE */: true,
        ];

    size_t i;
    for (i = 0; ; ++i)
    {
        if (!(i in KEEP_CAPS))
        {
            // test if capabilitiy exists
            if (prctl(PR_CAPBSET_READ, i, 0, 0, 0) < 0)
                break;
            if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0) < 0)
                stderr.writefln("failed to drop capability:%d", i);
        }
    }
    errnoEnforce(i > 0, "failed to drop capabilities");
}

int main(string[] args)
{
    string root;
    string[] bind, robind;
    bool umount;
    arraySep = ",";

    auto helpInformation = args.getopt(
        std.getopt.config.caseSensitive,
        std.getopt.config.required,
        "root", &root,
        "bind", &bind,
        "robind", &robind,
        "umount", &umount,
        );
    if (helpInformation.helpWanted)
    {
        usage(helpInformation.options);
        return EXIT_SUCCESS;
    }

    // cleanup root
    if (!root.isAbsolute)
    {
        stderr.writeln("--root must be an absolute path");
        return EXIT_FAILURE;
    }

    if (umount)
    {
        if (!isDir(root))
        {
            stderr.writeln("root does not exist, cowardly refusing to unmount");
            return EXIT_FAILURE;
        }
        auto mount = executeShell("LANG=C mount");
        foreach (line; mount.output.splitter('\n'))
            if (auto r = line.matchFirst(root ~ r"/([^ ]+)"))
                executeShell("umount " ~ buildPath(root, r[1]));

        return EXIT_SUCCESS;
    }

    // create directories
    mkdirRecurse(root);
    foreach (dir; NEWDIRS ~ TEMPDIRS)
        mkdirRecurse(buildPath(root, dir));

    // chmod the temporary directories
    foreach (dir; TEMPDIRS)
    {
        immutable path = buildPath(root, dir);
        errnoEnforce(chmod(path.toStringz, octal!777) == 0,
                     "failed to chmod " ~ path);
    }

    // copy files
    foreach (file; COPYFILES)
    {
        immutable path = buildPath(root, file);
        if (!exists(path))
            std.file.copy(buildPath("/", file), path, Yes.preserveAttributes);
    }

    // bind the directories
    foreach (dir; BINDDIRS)
    {
        // skip if non-exist bind directories.
        if (!exists(buildPath("/", dir)))
            continue;

        immutable path = buildPath(root, dir);
        if (buildPath("/", dir).isSymlink)
        {
            if (!path.isSymlink)
            {
                if (dir.isAbsolute)
                    mkdirRecurse(path);
                auto dest = readLink(buildPath("/", dir));
                symlink(dest, path);
            }
            assert(path.isDir);
        }
        else
        {
            mkdirRecurse(path);
            if (isEmptyDir(path))
            {
                executeShell("mount --bind " ~ buildPath("/", dir) ~ " " ~ path);
                executeShell("mount -o remount,ro,bind " ~ path);
            }
        }
    }

    // bind the custom directories
    foreach (dir; bind)
        bindCustom(root, dir, false);
    foreach (dir; robind)
        bindCustom(root, dir, true);

    // create symlinks
    try
    {
        symlink("../run/lock", buildPath(root, "var/lock"));
    }
    catch (FileException)
    {
        // Just ignore if symlink alreadly exists...
    }

    // create devices
    mkdirRecurse(buildPath(root, "dev"));
    if (!exists(buildPath(root, "dev/null")))
        executeShell("mknod -m 666 " ~ buildPath(root, "dev/null") ~ " c 1 3");
    if (!exists(buildPath(root, "dev/zero")))
        executeShell("mknod -m 666 " ~ buildPath(root, "dev/zero") ~ " c 1 5");
    foreach (file; ["random", "urandom"])
        if (!exists(buildPath(root, "dev", file)))
            executeShell("mknod -m 444 " ~ buildPath(root, "dev", file) ~ " c 1 9");

    // just print the status if no args
    if (args.length < 2)
    {
        writeln("jail is ready!");
        return EXIT_SUCCESS;
    }

    errnoEnforce(chroot(root.toStringz) == 0, "failed to chroot to " ~ root);
    chdir("/");
    dropCapabilities();
    execvp(args[1], args[1 .. $]);
    assert(false, "failed to exec: " ~ args[1]);
}
